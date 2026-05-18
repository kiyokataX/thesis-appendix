"""签名交易模型。

每笔交易由 (sender, recipient, amount, nonce) 构成 payload，
签名是 ECDSA(d_sender, SHA256(payload))。验证时任一节点用 sender 公钥独立验签。
"""
from __future__ import annotations
import hashlib
import json
from dataclasses import dataclass, asdict
from typing import Optional, Tuple

from src.ecc.curve import Point
from src.ecc import ecdsa


@dataclass
class Transaction:
    sender: str
    recipient: str
    amount: int
    nonce: int  # 防重放
    signature: Optional[Tuple[int, int]] = None  # (r, s)

    def _payload(self) -> bytes:
        d = {
            "sender": self.sender,
            "recipient": self.recipient,
            "amount": self.amount,
            "nonce": self.nonce,
        }
        return json.dumps(d, sort_keys=True).encode("utf-8")

    def hash(self) -> bytes:
        return hashlib.sha256(self._payload()).digest()

    def sign(self, private_key: int) -> None:
        self.signature = ecdsa.sign(private_key, self._payload())

    def verify(self, sender_public_key: Point) -> bool:
        if self.signature is None:
            return False
        return ecdsa.verify(sender_public_key, self._payload(), self.signature)

    def to_dict(self) -> dict:
        d = asdict(self)
        if self.signature is not None:
            d["signature"] = [hex(self.signature[0]), hex(self.signature[1])]
        return d
