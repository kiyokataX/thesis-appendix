"""
ECDSA 签名/验签算法 (基于任意 Weierstrass 曲线，默认 secp256k1)。

包含 RFC 6979 确定性 k 派生，避免随机数失败导致的私钥泄漏 (PS3 类事件)。
"""
from __future__ import annotations
import hashlib
import hmac
import secrets
from typing import Tuple

from .curve import Curve, Point
from .secp256k1 import SECP256K1
from src.utils.math_ops import mod_inverse


def _bits2int(data: bytes, qlen: int) -> int:
    """RFC 6979 §2.3.2: bits2int 转换。"""
    x = int.from_bytes(data, "big")
    bias = len(data) * 8 - qlen
    if bias > 0:
        x >>= bias
    return x


def _int2octets(x: int, rolen: int) -> bytes:
    return x.to_bytes(rolen, "big")


def _bits2octets(data: bytes, q: int, qlen: int, rolen: int) -> bytes:
    z1 = _bits2int(data, qlen)
    z2 = z1 % q
    return _int2octets(z2, rolen)


def _rfc6979_k(d: int, message_hash: bytes, q: int) -> int:
    """根据 RFC 6979 (HMAC-SHA256) 派生确定性 k。

    Args:
        d: 私钥
        message_hash: 消息的 SHA-256 哈希 (32 字节)
        q: 子群阶
    """
    qlen = q.bit_length()
    rolen = (qlen + 7) // 8
    hashlen = 32  # SHA-256

    bx = _int2octets(d, rolen) + _bits2octets(message_hash, q, qlen, rolen)

    V = b"\x01" * hashlen
    K = b"\x00" * hashlen
    K = hmac.new(K, V + b"\x00" + bx, hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()
    K = hmac.new(K, V + b"\x01" + bx, hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()

    while True:
        T = b""
        while len(T) < rolen:
            V = hmac.new(K, V, hashlib.sha256).digest()
            T += V
        k = _bits2int(T, qlen)
        if 1 <= k < q:
            return k
        K = hmac.new(K, V + b"\x00", hashlib.sha256).digest()
        V = hmac.new(K, V, hashlib.sha256).digest()


def public_key(d: int, curve: Curve = SECP256K1) -> Point:
    """从私钥导出公钥 Q = d * G。"""
    if not (1 <= d < curve.n):
        raise ValueError("私钥 d 必须 ∈ [1, n)")
    G = Point(curve.Gx, curve.Gy, curve)
    return d * G


def sign(
    d: int,
    message: bytes,
    curve: Curve = SECP256K1,
    deterministic: bool = True,
    low_s: bool = True,
) -> Tuple[int, int]:
    """ECDSA 签名。

    Args:
        d: 私钥 (整数, 1 ≤ d < n)。
        message: 待签名消息字节串 (内部会做 SHA-256)。
        curve: 椭圆曲线参数。
        deterministic: True 使用 RFC 6979 派生 k (推荐)；False 使用 secrets.randbelow。
        low_s: True 强制 s ≤ n/2 (BIP-62 防签名延展性)。
    Returns:
        签名 (r, s)。
    """
    if not (1 <= d < curve.n):
        raise ValueError("私钥 d 必须 ∈ [1, n)")
    G = Point(curve.Gx, curve.Gy, curve)
    msg_hash = hashlib.sha256(message).digest()
    z = _bits2int(msg_hash, curve.n.bit_length()) % curve.n

    while True:
        if deterministic:
            k = _rfc6979_k(d, msg_hash, curve.n)
        else:
            k = secrets.randbelow(curve.n - 1) + 1
        R = k * G
        if R.is_infinity():
            continue
        r = R.x % curve.n
        if r == 0:
            continue
        k_inv = mod_inverse(k, curve.n)
        s = (k_inv * (z + d * r)) % curve.n
        if s == 0:
            continue
        if low_s and s > curve.n // 2:
            s = curve.n - s
        return r, s


def _scalar_mul_raw(k: int, P: Point) -> Point:
    """不做阶归约的标量乘法，用于公钥阶验证。"""
    if k < 0:
        return _scalar_mul_raw(-k, -P)
    result = Point.infinity(P.curve)
    addend = P
    while k > 0:
        if k & 1:
            result = result + addend
        addend = addend + addend
        k >>= 1
    return result


def _is_valid_public_key(Q: Point, curve: Curve) -> bool:
    """检查 ECDSA 公钥是否落在指定曲线的基点子群中。"""
    if Q.curve != curve or Q.is_infinity():
        return False
    try:
        return _scalar_mul_raw(curve.n, Q).is_infinity()
    except (TypeError, ValueError, ZeroDivisionError):
        return False


def verify_digest(
    Q: Point,
    z: int,
    signature: Tuple[int, int],
    curve: Curve = SECP256K1,
) -> bool:
    """ECDSA 验签，直接接收已截断归约的摘要整数 z。

    该接口用于比特币等场景：调用方已经按协议构造 sighash，并完成双 SHA-256
    与按 n 截断/归约，验签时不应再对原消息做一次 SHA-256。
    """
    r, s = signature
    if not (1 <= r < curve.n and 1 <= s < curve.n):
        return False
    if not _is_valid_public_key(Q, curve):
        return False
    G = Point(curve.Gx, curve.Gy, curve)

    z %= curve.n
    s_inv = mod_inverse(s, curve.n)
    u1 = (z * s_inv) % curve.n
    u2 = (r * s_inv) % curve.n
    V = u1 * G + u2 * Q
    if V.is_infinity():
        return False
    return (V.x % curve.n) == r


def verify(
    Q: Point,
    message: bytes,
    signature: Tuple[int, int],
    curve: Curve = SECP256K1,
) -> bool:
    """ECDSA 验签。

    Args:
        Q: 公钥点。
        message: 原消息字节串。
        signature: (r, s)。
        curve: 曲线参数。
    """
    msg_hash = hashlib.sha256(message).digest()
    z = _bits2int(msg_hash, curve.n.bit_length()) % curve.n
    return verify_digest(Q, z, signature, curve)


if __name__ == "__main__":
    import secrets as _s
    print("== ECDSA 自测 (secp256k1) ==")
    d = _s.randbelow(SECP256K1.n - 1) + 1
    Q = public_key(d)
    msg = b"Hello, secp256k1!"
    sig = sign(d, msg)
    print(f"签名 r = {hex(sig[0])[:24]}...")
    print(f"签名 s = {hex(sig[1])[:24]}...")
    print(f"验签 (合法): {verify(Q, msg, sig)}")
    print(f"验签 (篡改): {verify(Q, b'Hello, secp256k0!', sig)}")
    # 双确定性签名相等性测试
    sig2 = sign(d, msg)
    print(f"两次确定性签名相等: {sig == sig2}")
    print("✅ ECDSA 自测通过")
