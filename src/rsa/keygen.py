"""
RSA 密钥生成。

KeyGen(λ) 步骤:
    1. 选两个 λ/2 比特的素数 p, q
    2. n = p * q, φ(n) = (p-1)(q-1)
    3. 选公钥指数 e (默认 65537) 与 φ(n) 互素
    4. d = e^{-1} mod φ(n)
    5. 返回 PublicKey(n, e), PrivateKey(n, d, p, q)
"""
from __future__ import annotations
from dataclasses import dataclass

from src.utils.math_ops import generate_prime, mod_inverse


@dataclass(frozen=True)
class PublicKey:
    n: int
    e: int

    def __repr__(self) -> str:
        return f"PublicKey(n={self.n.bit_length()}-bit, e={self.e})"


@dataclass(frozen=True)
class PrivateKey:
    n: int
    d: int
    p: int  # 保留 (p, q) 用于 CRT 解密加速
    q: int

    def __repr__(self) -> str:
        return f"PrivateKey(n={self.n.bit_length()}-bit, ...)"


def keygen(bit_length: int = 2048, e: int = 65537) -> tuple[PublicKey, PrivateKey]:
    """生成 RSA 密钥对。

    Args:
        bit_length: 模数 n 的位长，常用 2048 / 3072 / 4096。
        e: 加密指数，默认 65537 (二进制仅含两个 1，加密最快)。
    Returns:
        (PublicKey, PrivateKey)。

    注意: 生成 2048 位密钥在纯 Python 下约耗时 1-2 秒。
    """
    if bit_length < 256:
        raise ValueError("RSA 密钥长度建议 ≥ 1024 位; 本实现强制 ≥ 256 位")

    half = bit_length // 2
    while True:
        p = generate_prime(half)
        q = generate_prime(bit_length - half)
        if p == q:
            continue
        n = p * q
        if n.bit_length() != bit_length:
            continue  # 偶尔差一位，重选
        phi_n = (p - 1) * (q - 1)
        try:
            d = mod_inverse(e, phi_n)
            break
        except ValueError:
            continue  # gcd(e, phi_n) != 1，重选

    return PublicKey(n, e), PrivateKey(n, d, p, q)
