"""Diffie-Hellman 密钥交换 (在 F_p^* 的大素数阶子群上)。"""
from __future__ import annotations
import secrets
from .domain import DomainParams, validate_subgroup_element


def generate_keypair(params: DomainParams) -> tuple[int, int]:
    """生成 (私钥 a, 公钥 A = g^a mod p)。"""
    a = secrets.randbelow(params.q - 1) + 1
    A = pow(params.g, a, params.p)
    return a, A


def shared_secret(my_priv: int, peer_pub: int, params: DomainParams) -> int:
    """计算共享密钥 K = peer_pub ^ my_priv mod p。"""
    validate_subgroup_element(peer_pub, params, "peer_pub")
    return pow(peer_pub, my_priv, params.p)
