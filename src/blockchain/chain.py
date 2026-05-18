"""极简区块链 (单节点, 单链, 无网络通信)。

提供: 创世区块、注册账户公钥、加入交易池、挖矿打包、整链验证。
"""
from __future__ import annotations
import logging
from typing import Dict, List

from src.ecc.curve import Point
from .accounts import Account
from .block import Block
from .tx import Transaction


log = logging.getLogger(__name__)


class Chain:
    """极简区块链。"""

    def __init__(self, difficulty: int = 16):
        """初始化。

        Args:
            difficulty: PoW 难度，对应区块哈希的前导十六进制零数 (≈ 4*difficulty 比特零)。
                        ⚠️ 注意: 难度按"十六进制零数"计算; 16 表示需要 hash 以 16 个 '0' 开头。
                        本实现把 difficulty 解释为"二进制位前导零数 / 4"，即 16 → hash 以 4 个 '0' 开头。
                        参见 _target_prefix。
        """
        self.difficulty = difficulty
        self.blocks: List[Block] = [self._genesis()]
        self.tx_pool: List[Transaction] = []
        self.public_keys: Dict[str, Point] = {}

    @staticmethod
    def _genesis() -> Block:
        return Block(index=0, prev_hash="0" * 64, transactions=[], timestamp=0.0)

    def __len__(self) -> int:
        return len(self.blocks)

    def tip(self) -> Block:
        return self.blocks[-1]

    def _target_prefix(self) -> str:
        """PoW 目标: hash 必须以这么多个 '0' 字符开头 (十六进制)。"""
        return "0" * max(1, self.difficulty // 4)

    def register_account(self, account: Account) -> None:
        """登记账户的公钥，使其成为可识别的发送方。"""
        self.public_keys[account.address] = account.public_key

    def add_to_pool(self, tx: Transaction) -> bool:
        """加入交易池前先验证签名合法。"""
        pub = self.public_keys.get(tx.sender)
        if pub is None:
            log.warning(f"sender {tx.sender[:12]}... 未注册公钥, 拒绝交易")
            return False
        if not tx.verify(pub):
            log.warning(f"交易 {tx.hash().hex()[:16]}... 签名验证失败, 拒绝")
            return False
        self.tx_pool.append(tx)
        return True

    def mine_block(self) -> Block:
        """打包当前交易池为新区块, 寻找满足 PoW 难度的 nonce。"""
        prev = self.tip()
        b = Block(
            index=prev.index + 1,
            prev_hash=prev.hash(),
            transactions=list(self.tx_pool),
        )
        target = self._target_prefix()
        while not b.hash().startswith(target):
            b.nonce += 1
        return b

    def append(self, block: Block) -> None:
        """把已挖好的区块追加到链上, 含连续性、PoW、签名三层校验。"""
        if block.prev_hash != self.tip().hash():
            raise ValueError("prev_hash 不连续")
        if not block.hash().startswith(self._target_prefix()):
            raise ValueError("PoW 不满足难度")
        for tx in block.transactions:
            pub = self.public_keys.get(tx.sender)
            if pub is None or not tx.verify(pub):
                raise ValueError("区块内含非法交易")
        self.blocks.append(block)
        # 清理交易池中已被打包的
        packed = {tx.hash() for tx in block.transactions}
        self.tx_pool = [t for t in self.tx_pool if t.hash() not in packed]

    def is_valid(self) -> bool:
        """校验整条链 (除创世外的所有区块的连续性、PoW、签名)。"""
        target = self._target_prefix()
        for i in range(1, len(self.blocks)):
            prev = self.blocks[i - 1]
            cur = self.blocks[i]
            if cur.prev_hash != prev.hash():
                return False
            if not cur.hash().startswith(target):
                return False
            for tx in cur.transactions:
                pub = self.public_keys.get(tx.sender)
                if pub is None or not tx.verify(pub):
                    return False
        return True
