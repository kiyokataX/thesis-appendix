"""
Merkle Tree 实现 (与比特币一致的双 SHA-256 节点哈希)。

每层把相邻两个哈希拼接后再哈希；当前层节点数为奇数时复制最后一个 (与 Bitcoin Core 一致)。
"""
from __future__ import annotations
import hashlib
from typing import List


def _h(data: bytes) -> bytes:
    """双 SHA-256，比特币区块链使用的标准哈希。"""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def merkle_root(leaves: List[bytes]) -> bytes:
    """计算给定叶子列表的 Merkle Root。

    叶子已经是字节串 (调用方负责，比如先把交易序列化或哈希)。
    若叶子已是 32 字节哈希，则不会被二次哈希作为叶子；最终 root 仍为根节点的双 SHA-256。
    """
    if not leaves:
        return b"\x00" * 32
    layer = [_h(leaf) for leaf in leaves]
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])
        layer = [_h(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
    return layer[0]


def merkle_proof(leaves: List[bytes], index: int) -> List[bytes]:
    """生成指定叶子的 Merkle 证明路径 (一系列兄弟哈希)。"""
    if not (0 <= index < len(leaves)):
        raise IndexError(f"index {index} 越界, len(leaves)={len(leaves)}")
    layer = [_h(leaf) for leaf in leaves]
    proof: List[bytes] = []
    idx = index
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])
        sibling_idx = idx ^ 1
        proof.append(layer[sibling_idx])
        idx //= 2
        layer = [_h(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
    return proof


def verify_proof(leaf: bytes, proof: List[bytes], index: int, root: bytes) -> bool:
    """根据 leaf + 证明路径 + 索引，验证根哈希是否匹配。"""
    h = _h(leaf)
    idx = index
    for sibling in proof:
        if idx % 2 == 0:
            h = _h(h + sibling)
        else:
            h = _h(sibling + h)
        idx //= 2
    return h == root
