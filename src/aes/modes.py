"""
AES 工作模式 (ECB / CBC) 与 PKCS#7 填充。

⚠️ ECB 不应在真实场景中使用 (会泄漏明文模式)。CBC 需要不可预测的 IV 且无完整性保护,
真实部署应使用带认证加密的模式 (如 AES-GCM)。
"""
from __future__ import annotations
import secrets

from .aes import encrypt_block, decrypt_block


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """PKCS#7 填充: 不足 block_size 的余量用 (block_size - len%block_size) 填到末尾。

    若 data 已是 block_size 倍数, 仍追加 block_size 字节 (避免歧义)。
    """
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes) -> bytes:
    """去除 PKCS#7 填充。"""
    if not data:
        raise ValueError("数据为空, 无法去填充")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("无效的 PKCS#7 填充长度")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("PKCS#7 填充字节不一致")
    return data[:-pad_len]


def ecb_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """AES-ECB 加密 (含 PKCS#7 填充)。"""
    padded = pkcs7_pad(plaintext)
    return b"".join(encrypt_block(padded[i:i + 16], key) for i in range(0, len(padded), 16))


def ecb_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """AES-ECB 解密 (含 PKCS#7 去填充)。"""
    if len(ciphertext) % 16 != 0:
        raise ValueError("密文长度必须是 16 的倍数")
    plain = b"".join(decrypt_block(ciphertext[i:i + 16], key) for i in range(0, len(ciphertext), 16))
    return pkcs7_unpad(plain)


def cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes | None = None) -> tuple[bytes, bytes]:
    """AES-CBC 加密。返回 (iv, ciphertext)。

    若不提供 iv, 自动生成 16 字节随机 iv (推荐)。
    """
    if iv is None:
        iv = secrets.token_bytes(16)
    if len(iv) != 16:
        raise ValueError("IV 必须 16 字节")
    padded = pkcs7_pad(plaintext)
    blocks = []
    prev = iv
    for i in range(0, len(padded), 16):
        block = bytes(a ^ b for a, b in zip(padded[i:i + 16], prev))
        prev = encrypt_block(block, key)
        blocks.append(prev)
    return iv, b"".join(blocks)


def cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-CBC 解密。"""
    if len(iv) != 16:
        raise ValueError("IV 必须 16 字节")
    if len(ciphertext) % 16 != 0 or not ciphertext:
        raise ValueError("密文长度必须是 16 的非零倍数")
    blocks = []
    prev = iv
    for i in range(0, len(ciphertext), 16):
        cipher_block = ciphertext[i:i + 16]
        plain_block = decrypt_block(cipher_block, key)
        blocks.append(bytes(a ^ b for a, b in zip(plain_block, prev)))
        prev = cipher_block
    return pkcs7_unpad(b"".join(blocks))
