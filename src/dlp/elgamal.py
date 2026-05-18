"""ElGamal 公钥加密 (基于 DLP)。"""
from __future__ import annotations
import secrets

from .domain import DomainParams, validate_subgroup_element
from src.utils.math_ops import mod_inverse


def keygen(params: DomainParams) -> tuple[int, int]:
    """生成 (私钥 x, 公钥 y = g^x mod p)。"""
    x = secrets.randbelow(params.q - 1) + 1
    y = pow(params.g, x, params.p)
    return x, y


def encrypt(pub_y: int, m: int, params: DomainParams) -> tuple[int, int]:
    """ElGamal 加密。

    随机选 k, 输出 (c1, c2) = (g^k, m * y^k)。
    """
    validate_subgroup_element(pub_y, params, "pub_y")
    if not (1 <= m < params.p):
        raise ValueError("明文 m 必须 ∈ [1, p)")
    k = secrets.randbelow(params.q - 1) + 1
    c1 = pow(params.g, k, params.p)
    c2 = (m * pow(pub_y, k, params.p)) % params.p
    return c1, c2


def decrypt(priv_x: int, ciphertext: tuple[int, int], params: DomainParams) -> int:
    """ElGamal 解密: m = c2 * (c1^x)^{-1} mod p。"""
    c1, c2 = ciphertext
    validate_subgroup_element(c1, params, "ciphertext c1")
    s = pow(c1, priv_x, params.p)
    s_inv = mod_inverse(s, params.p)
    return (c2 * s_inv) % params.p
