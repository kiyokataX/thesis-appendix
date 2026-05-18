"""
DSA 数字签名 (NIST FIPS 186-4) 含 RFC 6979 确定性 k 派生。
"""
from __future__ import annotations
import hashlib
import hmac
import secrets
from typing import Tuple

from .domain import DomainParams, is_valid_subgroup_element
from src.utils.math_ops import mod_inverse


def keygen(params: DomainParams) -> tuple[int, int]:
    """生成 (私钥 x, 公钥 y = g^x mod p)。"""
    x = secrets.randbelow(params.q - 1) + 1
    y = pow(params.g, x, params.p)
    return x, y


def _bits2int(data: bytes, qlen: int) -> int:
    """RFC 6979 §2.3.2 bits2int 转换。"""
    v = int.from_bytes(data, "big")
    bias = len(data) * 8 - qlen
    if bias > 0:
        v >>= bias
    return v


def _rfc6979_k(x: int, msg_hash: bytes, q: int) -> int:
    """RFC 6979 派生确定性 k (HMAC-SHA256)。"""
    qlen = q.bit_length()
    rolen = (qlen + 7) // 8
    bx = x.to_bytes(rolen, "big") + (_bits2int(msg_hash, qlen) % q).to_bytes(rolen, "big")

    V = b"\x01" * 32
    K = b"\x00" * 32
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


def sign(
    x: int,
    message: bytes,
    params: DomainParams,
    deterministic: bool = True,
) -> Tuple[int, int]:
    """DSA 签名。返回 (r, s)，二者均 ∈ [1, q)。"""
    msg_hash = hashlib.sha256(message).digest()
    z = _bits2int(msg_hash, params.q.bit_length()) % params.q

    while True:
        k = _rfc6979_k(x, msg_hash, params.q) if deterministic \
            else secrets.randbelow(params.q - 1) + 1
        r = pow(params.g, k, params.p) % params.q
        if r == 0:
            continue
        k_inv = mod_inverse(k, params.q)
        s = (k_inv * (z + x * r)) % params.q
        if s == 0:
            continue
        return r, s


def verify(
    y: int,
    message: bytes,
    signature: Tuple[int, int],
    params: DomainParams,
) -> bool:
    """DSA 验签。"""
    r, s = signature
    if not (1 <= r < params.q and 1 <= s < params.q):
        return False
    if not is_valid_subgroup_element(y, params):
        return False
    msg_hash = hashlib.sha256(message).digest()
    z = _bits2int(msg_hash, params.q.bit_length()) % params.q
    w = mod_inverse(s, params.q)
    u1 = (z * w) % params.q
    u2 = (r * w) % params.q
    v = (pow(params.g, u1, params.p) * pow(y, u2, params.p)) % params.p
    return (v % params.q) == r
