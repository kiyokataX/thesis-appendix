"""
ECIES (Elliptic Curve Integrated Encryption Scheme) 教学简化版。

核心思想: ECDH 派生共享秘密, 经 KDF 切分成对称加密密钥与 MAC 密钥,
随后用对称加密 (本实现为 SHA-256 keystream + XOR) + HMAC 完成机密性 + 完整性保护。

工业标准 ECIES 通常用 AES-CTR/GCM + HKDF + HMAC, 本简化版使用更易理解的同等结构。
"""
from __future__ import annotations
import hashlib
import hmac
import secrets
from typing import Tuple

from .curve import Curve, Point
from .secp256k1 import SECP256K1


def _kdf(shared_x: int) -> Tuple[bytes, bytes]:
    """从共享秘密派生 (enc_key, mac_key)。"""
    seed = shared_x.to_bytes(32, "big")
    k = hashlib.sha256(seed).digest()  # 32 字节
    return k[:16], k[16:]


def _keystream(enc_key: bytes, length: int) -> bytes:
    """以 enc_key 为种子, 用 SHA-256 计数模式扩展出指定长度的字节流。"""
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(enc_key + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def encrypt(
    Y_recipient: Point,
    message: bytes,
    curve: Curve = SECP256K1,
) -> Tuple[Point, bytes, bytes]:
    """ECIES 加密。

    Args:
        Y_recipient: 接收方公钥点。
        message: 明文字节串。
    Returns:
        (R, ciphertext, tag)
            R = r*G        : 临时公钥
            ciphertext     : 同长度的密文
            tag            : HMAC-SHA256 完整性标签
    """
    if Y_recipient.is_infinity():
        raise ValueError("接收方公钥不能是无穷远点")
    G = Point(curve.Gx, curve.Gy, curve)
    r = secrets.randbelow(curve.n - 1) + 1
    R = r * G
    S = r * Y_recipient
    enc_key, mac_key = _kdf(S.x)

    keystream = _keystream(enc_key, len(message))
    ciphertext = bytes(a ^ b for a, b in zip(message, keystream))
    tag = hmac.new(mac_key, ciphertext, hashlib.sha256).digest()
    return R, ciphertext, tag


def decrypt(
    y_priv: int,
    encrypted: Tuple[Point, bytes, bytes],
    curve: Curve = SECP256K1,
) -> bytes:
    """ECIES 解密。MAC 验证失败抛出 ValueError。"""
    R, ciphertext, tag = encrypted
    if R.is_infinity():
        raise ValueError("临时公钥 R 不能是无穷远点")
    S = y_priv * R
    enc_key, mac_key = _kdf(S.x)

    expected_tag = hmac.new(mac_key, ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(expected_tag, tag):
        raise ValueError("MAC 验证失败 — 密文已被篡改或密钥不匹配")
    keystream = _keystream(enc_key, len(ciphertext))
    return bytes(a ^ b for a, b in zip(ciphertext, keystream))
