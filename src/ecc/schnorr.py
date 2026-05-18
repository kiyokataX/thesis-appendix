"""
Schnorr 签名 (椭圆曲线版, 教学简化版)。

签名: R = kG, e = SHA256(R.x || Q.x || m), s = (k + e*d) mod n,  输出 (R, s)
验证: e = SHA256(R.x || Q.x || m), 检查 s*G ?= R + e*Q

关键性质: **线性性 (Linearity)**
    若 σ_A = (R_A, s_A) 是 Alice 对 m 的签名,
       σ_B = (R_B, s_B) 是 Bob 对 m 的签名,
    则 (R_A + R_B, s_A + s_B) 是聚合公钥 Q_A + Q_B 对 m 的签名。
此性质是多重签名聚合 (MuSig) 与 Bitcoin Taproot 升级 (BIP-340) 的基础。

注: 本实现为教学版, 与 BIP-340 标准 (使用 x-only 公钥与 tagged hash) 有结构差异。
"""
from __future__ import annotations
import hashlib
from typing import Tuple

from .curve import Curve, Point
from .secp256k1 import SECP256K1


def _challenge(R: Point, Q: Point, message: bytes, n: int) -> int:
    """e = SHA256(R.x || Q.x || m) mod n。"""
    rx = R.x.to_bytes(32, "big")
    qx = Q.x.to_bytes(32, "big")
    h = hashlib.sha256(rx + qx + message).digest()
    return int.from_bytes(h, "big") % n


def public_key(d: int, curve: Curve = SECP256K1) -> Point:
    return d * Point(curve.Gx, curve.Gy, curve)


def sign(
    d: int,
    message: bytes,
    curve: Curve = SECP256K1,
) -> Tuple[Point, int]:
    """Schnorr 签名。

    使用确定性 k = SHA256(d || m) 派生 (与 BIP-340 思想一致, 但实现更简洁)。
    """
    if not (1 <= d < curve.n):
        raise ValueError("私钥 d 必须 ∈ [1, n)")
    G = Point(curve.Gx, curve.Gy, curve)
    Q = d * G

    seed = d.to_bytes(32, "big") + hashlib.sha256(message).digest()
    k = (int.from_bytes(hashlib.sha256(seed).digest(), "big") % (curve.n - 1)) + 1
    R = k * G
    e = _challenge(R, Q, message, curve.n)
    s = (k + e * d) % curve.n
    return R, s


def verify(
    Q: Point,
    message: bytes,
    signature: Tuple[Point, int],
    curve: Curve = SECP256K1,
) -> bool:
    """Schnorr 验签: 检查 s*G == R + e*Q。"""
    R, s = signature
    if R.is_infinity() or Q.is_infinity():
        return False
    if not (1 <= s < curve.n):
        return False
    G = Point(curve.Gx, curve.Gy, curve)
    e = _challenge(R, Q, message, curve.n)
    return s * G == R + e * Q


def aggregate(signatures: list[Tuple[Point, int]], curve: Curve = SECP256K1) -> Tuple[Point, int]:
    """演示线性聚合: 多签 (R_i, s_i) -> (ΣR_i, Σs_i mod n)。

    注意: 实际 MuSig 协议远比这复杂 (需要 nonce 协商防止 rogue-key 攻击),
    本函数仅用于演示数学线性性质。
    """
    if not signatures:
        raise ValueError("至少需要一个签名")
    R_sum = Point.infinity(curve)
    s_sum = 0
    for R, s in signatures:
        R_sum = R_sum + R
        s_sum = (s_sum + s) % curve.n
    return R_sum, s_sum
