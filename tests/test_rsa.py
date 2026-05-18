"""RSA 单元测试。"""
import pytest
from src.rsa import (
    keygen,
    decrypt,
    decrypt_oaep,
    encrypt,
    encrypt_oaep,
    sign,
    sign_pss,
    verify,
    verify_pss,
)


@pytest.fixture(scope="module")
def kp():
    """模块级 fixture: 仅生成一次密钥对 (1024 位以加快测试速度)。"""
    return keygen(bit_length=1024)


def test_keygen_bit_length(kp):
    pk, sk = kp
    assert pk.n.bit_length() == 1024
    assert sk.p * sk.q == pk.n


def test_encrypt_decrypt_roundtrip(kp):
    pk, sk = kp
    for m in [0, 1, 42, 12345, pk.n - 1]:
        c = encrypt(pk, m)
        assert decrypt(sk, c) == m


def test_sign_verify(kp):
    pk, sk = kp
    msg = b"thesis test message"
    sig = sign(sk, msg)
    assert verify(pk, msg, sig)
    assert not verify(pk, msg + b"!", sig)


def test_oaep_encrypt_decrypt_roundtrip(kp):
    pk, sk = kp
    msg = b"rsa oaep thesis demo"
    c1 = encrypt_oaep(pk, msg)
    c2 = encrypt_oaep(pk, msg)
    assert c1 != c2
    assert decrypt_oaep(sk, c1) == msg
    assert decrypt_oaep(sk, c2) == msg


def test_oaep_label_is_bound_to_ciphertext(kp):
    pk, sk = kp
    msg = b"label-bound message"
    c = encrypt_oaep(pk, msg, label=b"context-a")
    assert decrypt_oaep(sk, c, label=b"context-a") == msg
    with pytest.raises(ValueError):
        decrypt_oaep(sk, c, label=b"context-b")


def test_oaep_message_too_long(kp):
    pk, _ = kp
    with pytest.raises(ValueError):
        encrypt_oaep(pk, b"x" * 63)


def test_pss_sign_verify(kp):
    pk, sk = kp
    msg = b"rsa pss thesis demo"
    sig1 = sign_pss(sk, msg)
    sig2 = sign_pss(sk, msg)
    assert sig1 != sig2
    assert verify_pss(pk, msg, sig1)
    assert verify_pss(pk, msg, sig2)
    assert not verify_pss(pk, msg + b"!", sig1)


def test_encrypt_message_too_large(kp):
    pk, _ = kp
    with pytest.raises(ValueError):
        encrypt(pk, pk.n)
