"""
DLP 域参数生成与预置。

按 NIST FIPS 186-4 §A.1.1.2 思路: 先选大素数 q, 再找形如 q*k+1 的大素数 p,
最后构造阶恰为 q 的生成元 g = h^{(p-1)/q} mod p (h ≠ 1)。
"""
from __future__ import annotations
import secrets
from dataclasses import dataclass

from src.utils.math_ops import generate_prime, miller_rabin


@dataclass(frozen=True)
class DomainParams:
    """DLP 域参数 (p, q, g)。"""
    p: int   # 大素数模数
    q: int   # 子群阶 (大素数)
    g: int   # 阶为 q 的生成元

    def __repr__(self) -> str:
        return f"DomainParams(p={self.p.bit_length()}-bit, q={self.q.bit_length()}-bit)"


def is_valid_subgroup_element(y: int, params: DomainParams) -> bool:
    """检查 y 是否为 F_p^* 中非平凡的 q 阶子群元素。"""
    return 1 < y < params.p - 1 and pow(y, params.q, params.p) == 1


def validate_subgroup_element(
    y: int,
    params: DomainParams,
    name: str = "public key",
) -> None:
    """若 y 不是合法子群元素则抛出 ValueError。"""
    if not is_valid_subgroup_element(y, params):
        raise ValueError(f"{name} 必须满足 1 < y < p-1 且 y^q ≡ 1 (mod p)")


def generate_domain_params(p_bits: int = 256, q_bits: int = 64) -> DomainParams:
    """生成 DLP 域参数。

    教学/测试默认使用 256/64 的小尺寸 (秒级生成)。
    生产部署请用 NIST FIPS 186-4 推荐: 2048/256 或 3072/256。

    Args:
        p_bits: 模数 p 的位长。
        q_bits: 子群阶 q 的位长 (q 必须整除 p-1)。
    """
    if q_bits >= p_bits:
        raise ValueError("q_bits 必须 < p_bits")
    while True:
        q = generate_prime(q_bits)
        for _ in range(2000):
            # 随机生成 k 使 p = k*q + 1 长度恰为 p_bits
            k_bits = p_bits - q_bits
            k = (secrets.randbits(k_bits) | (1 << (k_bits - 1))) & ~1  # 偶数, 这样 k*q+1 才可能是奇素数
            p = k * q + 1
            if p.bit_length() != p_bits:
                continue
            if not miller_rabin(p):
                continue
            # 找阶为 q 的生成元
            for _ in range(100):
                h = secrets.randbelow(p - 3) + 2
                g = pow(h, (p - 1) // q, p)
                if g != 1:
                    return DomainParams(p, q, g)
            break  # 重新选 q
