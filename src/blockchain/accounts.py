"""账户模型: 持有 secp256k1 密钥对, 从公钥派生地址。"""
from __future__ import annotations
import hashlib
import secrets
from dataclasses import dataclass

from src.ecc.curve import Point
from src.ecc.secp256k1 import SECP256K1
from src.ecc.ecdsa import public_key as derive_public_key


def _address_from_public(Q: Point) -> str:
    """简化版地址 = SHA-256(SEC(Q)) 的前 20 字节十六进制 (类似 BTC P2PKH 但省略 RIPEMD160 与 Base58)。"""
    sec = b"\x04" + Q.x.to_bytes(32, "big") + Q.y.to_bytes(32, "big")
    digest = hashlib.sha256(sec).digest()[:20]
    return digest.hex()


@dataclass
class Account:
    private_key: int
    public_key: Point
    address: str

    @classmethod
    def generate(cls) -> "Account":
        """随机生成一个新账户。"""
        d = secrets.randbelow(SECP256K1.n - 1) + 1
        Q = derive_public_key(d)
        return cls(private_key=d, public_key=Q, address=_address_from_public(Q))

    def __repr__(self) -> str:
        return f"Account(addr={self.address[:12]}..., privkey=***)"
