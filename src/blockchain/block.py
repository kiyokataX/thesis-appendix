"""区块模型 (含 Merkle Root 与可挖矿的区块头)。"""
from __future__ import annotations
import hashlib
import time
from dataclasses import dataclass, field
from typing import List

from .merkle import merkle_root
from .tx import Transaction


@dataclass
class Block:
    index: int
    prev_hash: str
    transactions: List[Transaction]
    timestamp: float = field(default_factory=time.time)
    nonce: int = 0
    merkle_root_hex: str = ""

    def __post_init__(self) -> None:
        if not self.merkle_root_hex:
            self.merkle_root_hex = self.compute_merkle().hex()

    def compute_merkle(self) -> bytes:
        if not self.transactions:
            return b"\x00" * 32
        leaves = [tx.hash() for tx in self.transactions]
        return merkle_root(leaves)

    def header(self) -> bytes:
        """区块头序列化 (用于挖矿与哈希)。"""
        s = (
            f"{self.index}|{self.prev_hash}|{self.merkle_root_hex}|"
            f"{self.timestamp:.6f}|{self.nonce}"
        )
        return s.encode("utf-8")

    def hash(self) -> str:
        return hashlib.sha256(hashlib.sha256(self.header()).digest()).hexdigest()
