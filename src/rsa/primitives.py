"""
RSA 加密、解密、签名、验签。

本模块保留教科书 RSA 原语用于展示代数结构，并提供教学版 OAEP/PSS
封装用于演示真实方案为何需要随机化填充。生产环境应使用经过审计的
密码学库。
"""
from __future__ import annotations
import hashlib

from .keygen import PublicKey, PrivateKey
from .padding import oaep_decode, oaep_encode, pss_encode, pss_verify
from src.utils.math_ops import mod_inverse


def encrypt(pk: PublicKey, m: int) -> int:
    """RSA 加密: c = m^e mod n。"""
    if not (0 <= m < pk.n):
        raise ValueError("明文 m 必须在 [0, n) 范围内")
    return pow(m, pk.e, pk.n)


def decrypt(sk: PrivateKey, c: int) -> int:
    """RSA 解密 (CRT 加速)。

    直接版本: pow(c, sk.d, sk.n)
    CRT 版本: 在 mod p, mod q 下分别做半长度模幂再合并 (理论加速 4 倍)。
    """
    dp = sk.d % (sk.p - 1)
    dq = sk.d % (sk.q - 1)
    q_inv_p = mod_inverse(sk.q, sk.p)

    mp = pow(c, dp, sk.p)
    mq = pow(c, dq, sk.q)
    h = (q_inv_p * (mp - mq)) % sk.p
    return mq + h * sk.q


def sign(sk: PrivateKey, message: bytes) -> int:
    """RSA 签名: σ = H(m)^d mod n，H = SHA-256。"""
    h = int.from_bytes(hashlib.sha256(message).digest(), "big")
    h %= sk.n  # 确保 h < n
    return pow(h, sk.d, sk.n)


def verify(pk: PublicKey, message: bytes, signature: int) -> bool:
    """RSA 验签: 检查 σ^e mod n == H(m)。"""
    h = int.from_bytes(hashlib.sha256(message).digest(), "big")
    h %= pk.n
    return pow(signature, pk.e, pk.n) == h


def encrypt_oaep(
    pk: PublicKey,
    message: bytes,
    label: bytes = b"",
    seed: bytes | None = None,
) -> int:
    """RSA-OAEP 加密，返回整数密文。"""
    k = (pk.n.bit_length() + 7) // 8
    encoded = oaep_encode(message, k, label=label, seed=seed)
    m = int.from_bytes(encoded, "big")
    return encrypt(pk, m)


def decrypt_oaep(sk: PrivateKey, ciphertext: int, label: bytes = b"") -> bytes:
    """RSA-OAEP 解密，返回原始字节消息。"""
    k = (sk.n.bit_length() + 7) // 8
    m = decrypt(sk, ciphertext)
    encoded = m.to_bytes(k, "big")
    return oaep_decode(encoded, label=label)


def sign_pss(
    sk: PrivateKey,
    message: bytes,
    salt: bytes | None = None,
) -> int:
    """RSA-PSS 签名，返回整数签名。"""
    em_bits = sk.n.bit_length() - 1
    encoded = pss_encode(message, em_bits, salt=salt)
    m = int.from_bytes(encoded, "big")
    return pow(m, sk.d, sk.n)


def verify_pss(pk: PublicKey, message: bytes, signature: int) -> bool:
    """RSA-PSS 验签。"""
    if not (0 <= signature < pk.n):
        return False
    em_bits = pk.n.bit_length() - 1
    em_len = (em_bits + 7) // 8
    m = pow(signature, pk.e, pk.n)
    try:
        encoded = m.to_bytes(em_len, "big")
    except OverflowError:
        return False
    return pss_verify(message, encoded, em_bits)


if __name__ == "__main__":
    from .keygen import keygen
    print("== RSA 自测 (1024 位) ==")
    pk, sk = keygen(bit_length=1024)
    print(f"公钥: {pk}")

    # 加解密
    m = 42
    c = encrypt(pk, m)
    m_back = decrypt(sk, c)
    print(f"明文 {m} -> 密文 {hex(c)[:24]}... -> 解密 {m_back}")
    assert m_back == m

    # 签名验证
    msg = b"This is the thesis test message."
    sig = sign(sk, msg)
    ok = verify(pk, msg, sig)
    print(f"签名验证 (合法消息): {ok}")
    assert ok

    tampered = b"This is the thesis test message!"  # 改最后一字符
    ok2 = verify(pk, tampered, sig)
    print(f"签名验证 (篡改消息，应为 False): {ok2}")
    assert not ok2
    print("✅ RSA 自测通过")
