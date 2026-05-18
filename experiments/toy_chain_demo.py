"""
极简区块链端到端演示 (论文第 8.3 节实验)。

流程: 创建账户 -> 签名交易 -> 加入交易池 -> 矿工打包 -> 工作量证明 -> 整链验证。

用法:
    cd crypto_thesis
    python -m experiments.toy_chain_demo
"""
from __future__ import annotations
import logging
import time

from src.blockchain import Account, Chain, Transaction


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)


def main() -> None:
    print("=" * 60)
    print("极简区块链原型演示 (基于本文 secp256k1 + ECDSA)")
    print("=" * 60)

    # 难度 16 (hash 需以 4 个 '0' 开头), 单机几秒内可挖出
    chain = Chain(difficulty=16)

    # 1. 创建三个账户并注册公钥
    alice = Account.generate()
    bob = Account.generate()
    carol = Account.generate()
    for acc in (alice, bob, carol):
        chain.register_account(acc)
    print(f"\n[账户] Alice 地址: {alice.address}")
    print(f"[账户] Bob   地址: {bob.address}")
    print(f"[账户] Carol 地址: {carol.address}")

    # 2. 创建并签名两笔交易
    tx1 = Transaction(alice.address, bob.address, 50, nonce=0)
    tx1.sign(alice.private_key)
    tx2 = Transaction(bob.address, carol.address, 20, nonce=0)
    tx2.sign(bob.private_key)

    # 3. 加入交易池 (会触发 ECDSA 验签)
    assert chain.add_to_pool(tx1), "tx1 应通过验签"
    assert chain.add_to_pool(tx2), "tx2 应通过验签"
    print(f"\n[交易池] 当前包含 {len(chain.tx_pool)} 笔已验签交易")

    # 4. 挖矿打包
    print("\n[挖矿] 寻找满足 PoW 难度的 nonce ...")
    t0 = time.time()
    new_block = chain.mine_block()
    elapsed = time.time() - t0
    chain.append(new_block)
    print(f"[挖矿] 区块 #{new_block.index} 打包完成")
    print(f"      hash    : {new_block.hash()}")
    print(f"      nonce   : {new_block.nonce}")
    print(f"      merkle  : {new_block.merkle_root_hex}")
    print(f"      用时    : {elapsed:.2f} 秒")

    # 5. 整链验证
    print(f"\n[验证] 链长度: {len(chain)}, 整链验证: {chain.is_valid()}")

    # 6. 篡改测试: 把 alice -> bob 的金额改成 5000，验证应失败
    print("\n[篡改测试] 把 tx1.amount 从 50 改为 5000, 整链验证预期失败")
    chain.blocks[1].transactions[0].amount = 5000
    print(f"           篡改后整链验证: {chain.is_valid()}  (应为 False)")


if __name__ == "__main__":
    main()
