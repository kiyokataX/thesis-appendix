"""Blockchain 单元测试。"""
import pytest
from src.blockchain import Account, Transaction, Chain, merkle_root, merkle_proof, verify_proof


def test_merkle_basic():
    leaves = [b"hello", b"world", b"foo", b"bar"]
    root = merkle_root(leaves)
    assert len(root) == 32


def test_merkle_proof_roundtrip():
    leaves = [f"item{i}".encode() for i in range(7)]
    root = merkle_root(leaves)
    for i in range(len(leaves)):
        proof = merkle_proof(leaves, i)
        assert verify_proof(leaves[i], proof, i, root), f"index {i} 失败"


def test_account_generate_unique():
    a = Account.generate()
    b = Account.generate()
    assert a.address != b.address
    assert a.private_key != b.private_key


def test_signed_transaction():
    alice = Account.generate()
    tx = Transaction(alice.address, "deadbeef", 100, nonce=0)
    tx.sign(alice.private_key)
    assert tx.verify(alice.public_key)
    # 篡改: 改 amount 后验签应失败
    tx.amount = 200
    assert not tx.verify(alice.public_key)


def test_chain_mining_low_difficulty():
    chain = Chain(difficulty=8)  # 二位前导零, 极快
    alice = Account.generate()
    bob = Account.generate()
    chain.register_account(alice)
    chain.register_account(bob)

    tx = Transaction(alice.address, bob.address, 10, nonce=0)
    tx.sign(alice.private_key)
    assert chain.add_to_pool(tx)

    block = chain.mine_block()
    chain.append(block)

    assert len(chain) == 2
    assert chain.is_valid()


def test_chain_rejects_invalid_signature():
    chain = Chain(difficulty=8)
    alice = Account.generate()
    bob = Account.generate()
    chain.register_account(alice)
    chain.register_account(bob)
    tx = Transaction(alice.address, bob.address, 10, nonce=0)
    # 用 Bob 的私钥签 Alice 的交易, 应被拒
    tx.sign(bob.private_key)
    assert not chain.add_to_pool(tx)
