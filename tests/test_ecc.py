"""ECC + ECDSA 单元测试 (基于 secp256k1)。"""
import hashlib
import pytest
import secrets

from src.ecc.curve import Point, Curve
from src.ecc.secp256k1 import SECP256K1, base_point
from src.ecc import ecdsa


def test_base_point_on_curve():
    G = base_point()
    assert not G.is_infinity()


def test_n_times_G_is_infinity():
    """n * G == O (基点的阶为 n)。"""
    G = base_point()
    assert (SECP256K1.n * G).is_infinity()


def test_double_and_add_consistency():
    """k * G 用 Double-and-Add 与逐步累加 (小 k) 应一致。"""
    G = base_point()
    # 小 k 用线性累加
    cur = Point.infinity(SECP256K1)
    for k in range(0, 30):
        assert k * G == cur, f"k={k} 不一致"
        cur = cur + G


def test_point_inverse():
    G = base_point()
    assert (G + (-G)).is_infinity()
    assert (-G).x == G.x
    assert (-G).y == (SECP256K1.p - G.y)


def test_ecdsa_sign_verify_roundtrip():
    d = secrets.randbelow(SECP256K1.n - 1) + 1
    Q = ecdsa.public_key(d)
    msg = b"hello, ecdsa"
    sig = ecdsa.sign(d, msg)
    assert ecdsa.verify(Q, msg, sig)


def test_ecdsa_verify_digest_roundtrip():
    d = secrets.randbelow(SECP256K1.n - 1) + 1
    Q = ecdsa.public_key(d)
    msg = b"hello, verify digest"
    sig = ecdsa.sign(d, msg)
    z = int.from_bytes(hashlib.sha256(msg).digest(), "big") % SECP256K1.n
    assert ecdsa.verify_digest(Q, z, sig)
    assert not ecdsa.verify_digest(Q, (z + 1) % SECP256K1.n, sig)


def test_ecdsa_rejects_invalid_public_key():
    d = secrets.randbelow(SECP256K1.n - 1) + 1
    Q = ecdsa.public_key(d)
    msg = b"invalid public key"
    sig = ecdsa.sign(d, msg)
    z = int.from_bytes(hashlib.sha256(msg).digest(), "big") % SECP256K1.n

    assert not ecdsa.verify_digest(Point.infinity(SECP256K1), z, sig)

    wrong_curve = Curve(
        SECP256K1.p,
        SECP256K1.a,
        SECP256K1.b,
        SECP256K1.Gx,
        SECP256K1.Gy,
        SECP256K1.n - 1,
    )
    wrong_curve_Q = Point(Q.x, Q.y, wrong_curve)
    assert not ecdsa.verify_digest(wrong_curve_Q, z, sig)

    with pytest.raises(ValueError):
        Point(Q.x, (Q.y + 1) % SECP256K1.p, SECP256K1)


def test_ecdsa_tampered_message():
    d = secrets.randbelow(SECP256K1.n - 1) + 1
    Q = ecdsa.public_key(d)
    msg = b"hello, ecdsa"
    sig = ecdsa.sign(d, msg)
    assert not ecdsa.verify(Q, msg + b"!", sig)


def test_ecdsa_deterministic():
    """RFC 6979: 相同 (d, msg) 必然产生相同签名。"""
    d = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
    msg = b"sample"
    sig1 = ecdsa.sign(d, msg, deterministic=True)
    sig2 = ecdsa.sign(d, msg, deterministic=True)
    assert sig1 == sig2


def test_ecdsa_low_s_form():
    """low_s=True 时 s 必然 ≤ n/2。"""
    d = secrets.randbelow(SECP256K1.n - 1) + 1
    msg = b"low s test"
    r, s = ecdsa.sign(d, msg, low_s=True)
    assert s <= SECP256K1.n // 2
