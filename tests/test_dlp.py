"""DLP 公钥体制 (DH / ElGamal / DSA) 单元测试。"""
import hashlib

import pytest
from src.dlp import generate_domain_params, dh, elgamal, dsa
from src.utils.math_ops import mod_inverse


@pytest.fixture(scope="module")
def params():
    """模块级 fixture: 生成一次小型域参数 (256/64) 用于测试。"""
    return generate_domain_params(p_bits=256, q_bits=64)


def test_domain_params_validity(params):
    # q | p - 1
    assert (params.p - 1) % params.q == 0
    # g 的阶为 q
    assert pow(params.g, params.q, params.p) == 1
    # g != 1
    assert params.g != 1


def test_dh_shared_secret(params):
    a, A = dh.generate_keypair(params)
    b, B = dh.generate_keypair(params)
    K_alice = dh.shared_secret(a, B, params)
    K_bob = dh.shared_secret(b, A, params)
    assert K_alice == K_bob


def test_dh_rejects_invalid_peer_public_key(params):
    a, _ = dh.generate_keypair(params)
    for invalid_peer_pub in (1, params.p - 1):
        with pytest.raises(ValueError):
            dh.shared_secret(a, invalid_peer_pub, params)


def test_elgamal_roundtrip(params):
    x, y = elgamal.keygen(params)
    for m in [1, 42, params.p - 2]:
        c = elgamal.encrypt(y, m, params)
        assert elgamal.decrypt(x, c, params) == m


def test_elgamal_probabilistic(params):
    """两次加密同一明文应得到不同密文 (概率加密)。"""
    x, y = elgamal.keygen(params)
    c1 = elgamal.encrypt(y, 42, params)
    c2 = elgamal.encrypt(y, 42, params)
    assert c1 != c2


def test_elgamal_rejects_invalid_public_key_and_c1(params):
    x, _ = elgamal.keygen(params)
    with pytest.raises(ValueError):
        elgamal.encrypt(1, 42, params)
    with pytest.raises(ValueError):
        elgamal.decrypt(x, (1, 42), params)


def test_dsa_sign_verify(params):
    x, y = dsa.keygen(params)
    msg = b"DSA test message"
    sig = dsa.sign(x, msg, params)
    assert dsa.verify(y, msg, sig, params)


def test_dsa_tampered_message(params):
    x, y = dsa.keygen(params)
    msg = b"DSA test"
    sig = dsa.sign(x, msg, params)
    assert not dsa.verify(y, msg + b"!", sig, params)


def test_dsa_rejects_invalid_public_key(params):
    x, y = dsa.keygen(params)
    msg = b"DSA invalid public key"
    sig = dsa.sign(x, msg, params)
    assert dsa.verify(y, msg, sig, params)
    assert not dsa.verify(1, msg, sig, params)
    assert not dsa.verify(params.p - 1, msg, sig, params)


def test_dsa_deterministic_k(params):
    """RFC 6979: 相同 (x, msg) 必然产生相同签名。"""
    x, y = dsa.keygen(params)
    msg = b"deterministic test"
    sig1 = dsa.sign(x, msg, params, deterministic=True)
    sig2 = dsa.sign(x, msg, params, deterministic=True)
    assert sig1 == sig2


def test_dsa_reused_k_leaks_private_key(params, monkeypatch):
    """同一私钥复用 k 签两个消息时，可由两组签名代数恢复私钥 x。"""
    x, _ = dsa.keygen(params)
    fixed_k = next(
        k for k in range(2, 1000)
        if pow(params.g, k, params.p) % params.q != 0
    )
    monkeypatch.setattr(dsa, "_rfc6979_k", lambda *_args: fixed_k)

    msg1 = b"DSA reused k message 1"
    msg2 = b"DSA reused k message 2"
    r1, s1 = dsa.sign(x, msg1, params, deterministic=True)
    r2, s2 = dsa.sign(x, msg2, params, deterministic=True)
    assert r1 == r2

    z1 = dsa._bits2int(hashlib.sha256(msg1).digest(), params.q.bit_length()) % params.q
    z2 = dsa._bits2int(hashlib.sha256(msg2).digest(), params.q.bit_length()) % params.q
    recovered_k = ((z1 - z2) * mod_inverse((s1 - s2) % params.q, params.q)) % params.q
    recovered_x = ((s1 * recovered_k - z1) * mod_inverse(r1, params.q)) % params.q

    assert recovered_k == fixed_k
    assert recovered_x == x
