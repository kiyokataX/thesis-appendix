"""Teaching implementations of OAEP and PSS encodings for RSA.

The routines below follow the structure of PKCS #1 encodings closely enough for
the thesis demos, but they are not a replacement for audited cryptographic
libraries in production systems.
"""
from __future__ import annotations

import hashlib
import secrets
from hmac import compare_digest


def _hash(data: bytes, hash_name: str) -> bytes:
    return hashlib.new(hash_name, data).digest()


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def mgf1(seed: bytes, length: int, hash_name: str = "sha256") -> bytes:
    """Mask Generation Function MGF1."""
    if length < 0:
        raise ValueError("mask length must be non-negative")

    h_len = hashlib.new(hash_name).digest_size
    output = bytearray()
    counter = 0
    while len(output) < length:
        c = counter.to_bytes(4, "big")
        output.extend(_hash(seed + c, hash_name))
        counter += 1
    return bytes(output[:length])


def oaep_encode(
    message: bytes,
    k: int,
    label: bytes = b"",
    seed: bytes | None = None,
    hash_name: str = "sha256",
) -> bytes:
    """Encode a message with OAEP.

    Args:
        message: Plaintext bytes.
        k: RSA modulus length in bytes.
        label: Optional protocol label bound into the encoding.
        seed: Optional hLen-byte seed for deterministic tests.
        hash_name: Hash function used by OAEP and MGF1.
    """
    h_len = hashlib.new(hash_name).digest_size
    if len(message) > k - 2 * h_len - 2:
        raise ValueError("message too long for OAEP encoding")

    if seed is None:
        seed = secrets.token_bytes(h_len)
    if len(seed) != h_len:
        raise ValueError("OAEP seed length must equal hash output length")

    l_hash = _hash(label, hash_name)
    ps = b"\x00" * (k - len(message) - 2 * h_len - 2)
    db = l_hash + ps + b"\x01" + message
    db_mask = mgf1(seed, k - h_len - 1, hash_name)
    masked_db = _xor_bytes(db, db_mask)
    seed_mask = mgf1(masked_db, h_len, hash_name)
    masked_seed = _xor_bytes(seed, seed_mask)
    return b"\x00" + masked_seed + masked_db


def oaep_decode(encoded: bytes, label: bytes = b"", hash_name: str = "sha256") -> bytes:
    """Decode and verify an OAEP-encoded message."""
    h_len = hashlib.new(hash_name).digest_size
    if len(encoded) < 2 * h_len + 2:
        raise ValueError("OAEP encoded message is too short")

    y = encoded[0]
    masked_seed = encoded[1 : 1 + h_len]
    masked_db = encoded[1 + h_len :]
    seed_mask = mgf1(masked_db, h_len, hash_name)
    seed = _xor_bytes(masked_seed, seed_mask)
    db_mask = mgf1(seed, len(masked_db), hash_name)
    db = _xor_bytes(masked_db, db_mask)

    l_hash = _hash(label, hash_name)
    if y != 0 or not compare_digest(db[:h_len], l_hash):
        raise ValueError("invalid OAEP encoding")

    rest = db[h_len:]
    try:
        delimiter = rest.index(b"\x01")
    except ValueError as exc:
        raise ValueError("invalid OAEP encoding") from exc
    if any(rest[:delimiter]):
        raise ValueError("invalid OAEP encoding")
    return rest[delimiter + 1 :]


def pss_encode(
    message: bytes,
    em_bits: int,
    salt: bytes | None = None,
    hash_name: str = "sha256",
) -> bytes:
    """Encode a message with EMSA-PSS."""
    h_len = hashlib.new(hash_name).digest_size
    s_len = h_len if salt is None else len(salt)
    em_len = (em_bits + 7) // 8
    if em_len < h_len + s_len + 2:
        raise ValueError("encoded message too short for PSS")

    if salt is None:
        salt = secrets.token_bytes(s_len)

    m_hash = _hash(message, hash_name)
    h = _hash(b"\x00" * 8 + m_hash + salt, hash_name)
    ps = b"\x00" * (em_len - s_len - h_len - 2)
    db = ps + b"\x01" + salt
    db_mask = mgf1(h, em_len - h_len - 1, hash_name)
    masked_db = bytearray(_xor_bytes(db, db_mask))

    unused_bits = 8 * em_len - em_bits
    if unused_bits:
        masked_db[0] &= 0xFF >> unused_bits
    return bytes(masked_db) + h + b"\xbc"


def pss_verify(
    message: bytes,
    encoded: bytes,
    em_bits: int,
    salt_length: int | None = None,
    hash_name: str = "sha256",
) -> bool:
    """Verify an EMSA-PSS encoded message."""
    h_len = hashlib.new(hash_name).digest_size
    s_len = h_len if salt_length is None else salt_length
    em_len = (em_bits + 7) // 8
    if len(encoded) != em_len or em_len < h_len + s_len + 2:
        return False
    if encoded[-1] != 0xBC:
        return False

    masked_db = bytearray(encoded[: em_len - h_len - 1])
    h = encoded[em_len - h_len - 1 : -1]
    unused_bits = 8 * em_len - em_bits
    if unused_bits and masked_db[0] >> (8 - unused_bits):
        return False

    db_mask = mgf1(h, em_len - h_len - 1, hash_name)
    db = bytearray(_xor_bytes(masked_db, db_mask))
    if unused_bits:
        db[0] &= 0xFF >> unused_bits

    ps_len = em_len - h_len - s_len - 2
    if any(db[:ps_len]) or db[ps_len] != 0x01:
        return False

    salt = bytes(db[-s_len:]) if s_len else b""
    m_hash = _hash(message, hash_name)
    expected = _hash(b"\x00" * 8 + m_hash + salt, hash_name)
    return compare_digest(h, expected)
