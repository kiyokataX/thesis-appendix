"""Schnorr 签名与 ECIES 加密单元测试。"""
import secrets

from src.ecc.secp256k1 import SECP256K1
from src.ecc import schnorr, ecies


def test_schnorr_sign_verify():
    d = secrets.randbelow(SECP256K1.n - 1) + 1
    Q = schnorr.public_key(d)
    msg = b"hello, schnorr"
    sig = schnorr.sign(d, msg)
    assert schnorr.verify(Q, msg, sig)


def test_schnorr_tampered():
    d = secrets.randbelow(SECP256K1.n - 1) + 1
    Q = schnorr.public_key(d)
    sig = schnorr.sign(d, b"original")
    assert not schnorr.verify(Q, b"original!", sig)


def test_schnorr_linearity():
    """聚合签名: 使用同一个 challenge 时, σ_A + σ_B 可对 Q_A + Q_B 验签。"""
    msg = b"multisig test"
    d_a = secrets.randbelow(SECP256K1.n - 1) + 1
    d_b = secrets.randbelow(SECP256K1.n - 1) + 1
    k_a = secrets.randbelow(SECP256K1.n - 1) + 1
    k_b = secrets.randbelow(SECP256K1.n - 1) + 1

    Q_a = schnorr.public_key(d_a)
    Q_b = schnorr.public_key(d_b)
    G = schnorr.public_key(1)
    R_a = k_a * G
    R_b = k_b * G
    R_agg = R_a + R_b
    Q_agg = Q_a + Q_b

    e = schnorr._challenge(R_agg, Q_agg, msg, SECP256K1.n)
    sig_a = (R_a, (k_a + e * d_a) % SECP256K1.n)
    sig_b = (R_b, (k_b + e * d_b) % SECP256K1.n)
    sig_agg = schnorr.aggregate([sig_a, sig_b])

    assert schnorr.verify(Q_agg, msg, sig_agg)


def test_ecies_roundtrip():
    d = secrets.randbelow(SECP256K1.n - 1) + 1
    Y = schnorr.public_key(d)  # 复用 ecdsa.public_key 等价的工具

    msg = b"This is an ECIES-encrypted message."
    encrypted = ecies.encrypt(Y, msg)
    decrypted = ecies.decrypt(d, encrypted)
    assert decrypted == msg


def test_ecies_tampering_detected():
    import pytest
    d = secrets.randbelow(SECP256K1.n - 1) + 1
    Y = schnorr.public_key(d)
    R, ct, tag = ecies.encrypt(Y, b"sensitive data")
    # 篡改密文一字节
    bad_ct = bytes([ct[0] ^ 1]) + ct[1:]
    with pytest.raises(ValueError, match="MAC"):
        ecies.decrypt(d, (R, bad_ct, tag))
