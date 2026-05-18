"""
AES-128 (FIPS 197) 完整实现。

核心数据结构: 4x4 字节矩阵 State (按列优先存储, 与 FIPS 197 一致)。
轮数 Nr=10, 密钥 16 字节, 分组 16 字节。

S 盒由 GF(2^8) 乘法逆 + 仿射变换在模块加载时即时计算 (与论文 §3.3.2 对应)。
"""
from __future__ import annotations
from typing import List

from .gf2 import gf2_mul, gf2_inv


# ----- S 盒 (由 GF(2^8) 乘法逆 + 仿射变换构造) -----

def _build_sbox() -> tuple[List[int], List[int]]:
    """按 FIPS 197 §5.1.1 构造 S 盒与逆 S 盒。"""
    sbox = [0] * 256
    inv_sbox = [0] * 256
    for i in range(256):
        a = gf2_inv(i)  # 0 的"逆"约定为 0
        # 仿射变换: b'_i = b_i ⊕ b_{(i+4)%8} ⊕ b_{(i+5)%8} ⊕ b_{(i+6)%8} ⊕ b_{(i+7)%8} ⊕ c_i
        # 其中 c = 0x63
        result = 0
        for j in range(8):
            bit = (
                ((a >> j) & 1)
                ^ ((a >> ((j + 4) % 8)) & 1)
                ^ ((a >> ((j + 5) % 8)) & 1)
                ^ ((a >> ((j + 6) % 8)) & 1)
                ^ ((a >> ((j + 7) % 8)) & 1)
                ^ ((0x63 >> j) & 1)
            )
            result |= (bit & 1) << j
        sbox[i] = result
        inv_sbox[result] = i
    return sbox, inv_sbox


SBOX, INV_SBOX = _build_sbox()
# 自检: FIPS 197 标准 S 盒前几个值
assert SBOX[0x00] == 0x63 and SBOX[0x01] == 0x7C and SBOX[0x53] == 0xED, \
    "S 盒构造错误 — 与 FIPS 197 标准值不符"


# ----- 轮常数 Rcon -----

RCON = [0x01]
for _ in range(9):
    RCON.append(gf2_mul(RCON[-1], 0x02))  # GF(2^8) 中 ×x, 自动完成 mod m(x) 约简


def _mul_table(k: int) -> List[int]:
    """预计算 GF(2^8) 中固定常数 k 与所有字节的乘积。"""
    return [gf2_mul(k, x) for x in range(256)]


MUL2 = _mul_table(0x02)
MUL3 = _mul_table(0x03)
MUL9 = _mul_table(0x09)
MUL0B = _mul_table(0x0B)
MUL0D = _mul_table(0x0D)
MUL0E = _mul_table(0x0E)


def _sub_word(word: bytes) -> bytes:
    return bytes(SBOX[b] for b in word)


def _rot_word(word: bytes) -> bytes:
    return word[1:] + word[:1]


# ----- 密钥扩展 -----

def key_expansion(key: bytes) -> List[bytes]:
    """AES-128 密钥扩展: 16 字节用户密钥 -> 11 个 16 字节轮密钥。"""
    if len(key) != 16:
        raise ValueError("AES-128 密钥必须是 16 字节")
    Nk, Nr, Nb = 4, 10, 4
    W = [bytes(key[i:i + 4]) for i in range(0, 16, 4)]
    for i in range(Nk, Nb * (Nr + 1)):
        temp = W[i - 1]
        if i % Nk == 0:
            temp = _sub_word(_rot_word(temp))
            temp = bytes([temp[0] ^ RCON[i // Nk - 1]]) + temp[1:]
        W.append(bytes(a ^ b for a, b in zip(W[i - Nk], temp)))
    return [b"".join(W[i:i + 4]) for i in range(0, len(W), 4)]


# ----- State 与轮变换 -----

def _bytes_to_state(b: bytes) -> List[List[int]]:
    """16 字节 -> 4x4 矩阵 (按列优先, FIPS 197 标准约定)。"""
    return [[b[r + 4 * c] for c in range(4)] for r in range(4)]


def _state_to_bytes(state: List[List[int]]) -> bytes:
    return bytes(state[r][c] for c in range(4) for r in range(4))


def _sub_bytes(state: List[List[int]], box: List[int] = SBOX) -> List[List[int]]:
    return [[box[state[r][c]] for c in range(4)] for r in range(4)]


def _shift_rows(state: List[List[int]]) -> List[List[int]]:
    return [
        list(state[0]),
        state[1][1:] + state[1][:1],
        state[2][2:] + state[2][:2],
        state[3][3:] + state[3][:3],
    ]


def _inv_shift_rows(state: List[List[int]]) -> List[List[int]]:
    return [
        list(state[0]),
        state[1][-1:] + state[1][:-1],
        state[2][-2:] + state[2][:-2],
        state[3][-3:] + state[3][:-3],
    ]


def _mix_columns(state: List[List[int]]) -> List[List[int]]:
    new_state = [[0] * 4 for _ in range(4)]
    for c in range(4):
        s0, s1, s2, s3 = state[0][c], state[1][c], state[2][c], state[3][c]
        new_state[0][c] = MUL2[s0] ^ MUL3[s1] ^ s2 ^ s3
        new_state[1][c] = s0 ^ MUL2[s1] ^ MUL3[s2] ^ s3
        new_state[2][c] = s0 ^ s1 ^ MUL2[s2] ^ MUL3[s3]
        new_state[3][c] = MUL3[s0] ^ s1 ^ s2 ^ MUL2[s3]
    return new_state


def _inv_mix_columns(state: List[List[int]]) -> List[List[int]]:
    new_state = [[0] * 4 for _ in range(4)]
    for c in range(4):
        s0, s1, s2, s3 = state[0][c], state[1][c], state[2][c], state[3][c]
        new_state[0][c] = MUL0E[s0] ^ MUL0B[s1] ^ MUL0D[s2] ^ MUL9[s3]
        new_state[1][c] = MUL9[s0] ^ MUL0E[s1] ^ MUL0B[s2] ^ MUL0D[s3]
        new_state[2][c] = MUL0D[s0] ^ MUL9[s1] ^ MUL0E[s2] ^ MUL0B[s3]
        new_state[3][c] = MUL0B[s0] ^ MUL0D[s1] ^ MUL9[s2] ^ MUL0E[s3]
    return new_state


def _add_round_key(state: List[List[int]], round_key: bytes) -> List[List[int]]:
    rk_state = _bytes_to_state(round_key)
    return [[state[r][c] ^ rk_state[r][c] for c in range(4)] for r in range(4)]


# ----- 对外接口 -----

def _encrypt_block_with_round_keys(plaintext: bytes, rks: List[bytes]) -> bytes:
    """使用已扩展轮密钥加密一个 16 字节分组。"""
    if len(plaintext) != 16:
        raise ValueError("AES 分组必须是 16 字节")
    state = _bytes_to_state(plaintext)
    state = _add_round_key(state, rks[0])
    for r in range(1, 10):
        state = _sub_bytes(state)
        state = _shift_rows(state)
        state = _mix_columns(state)
        state = _add_round_key(state, rks[r])
    state = _sub_bytes(state)
    state = _shift_rows(state)
    state = _add_round_key(state, rks[10])
    return _state_to_bytes(state)


def _decrypt_block_with_round_keys(ciphertext: bytes, rks: List[bytes]) -> bytes:
    """使用已扩展轮密钥解密一个 16 字节分组。"""
    if len(ciphertext) != 16:
        raise ValueError("AES 分组必须是 16 字节")
    state = _bytes_to_state(ciphertext)
    state = _add_round_key(state, rks[10])
    for r in range(9, 0, -1):
        state = _inv_shift_rows(state)
        state = _sub_bytes(state, INV_SBOX)
        state = _add_round_key(state, rks[r])
        state = _inv_mix_columns(state)
    state = _inv_shift_rows(state)
    state = _sub_bytes(state, INV_SBOX)
    state = _add_round_key(state, rks[0])
    return _state_to_bytes(state)


def encrypt_block(plaintext: bytes, key: bytes) -> bytes:
    """AES-128 加密一个 16 字节分组。"""
    return _encrypt_block_with_round_keys(plaintext, key_expansion(key))


def decrypt_block(ciphertext: bytes, key: bytes) -> bytes:
    """AES-128 解密一个 16 字节分组。"""
    return _decrypt_block_with_round_keys(ciphertext, key_expansion(key))


class AES:
    """AES-128 面向对象封装。"""

    def __init__(self, key: bytes):
        if len(key) != 16:
            raise ValueError("仅支持 AES-128 (16 字节密钥)")
        self.key = key
        self._round_keys = key_expansion(key)

    def encrypt(self, plaintext: bytes) -> bytes:
        return _encrypt_block_with_round_keys(plaintext, self._round_keys)

    def decrypt(self, ciphertext: bytes) -> bytes:
        return _decrypt_block_with_round_keys(ciphertext, self._round_keys)
