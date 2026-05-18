"""AES-128 单元测试 (FIPS 197 标准向量)。"""
import pytest

from src.aes.gf2 import gf2_add, gf2_mul, gf2_inv
from src.aes.aes import (
    AES, encrypt_block, decrypt_block, key_expansion, SBOX, INV_SBOX,
)
from src.aes.modes import (
    pkcs7_pad, pkcs7_unpad, ecb_encrypt, ecb_decrypt, cbc_encrypt, cbc_decrypt,
)


# ----- GF(2^8) 运算 (论文 §2.3.2 例子) -----

def test_gf2_add():
    assert gf2_add(0x57, 0x83) == 0xD4


def test_gf2_mul_paper_example():
    """0x57 * 0x83 = 0xC1 (论文 §2.3.2)。"""
    assert gf2_mul(0x57, 0x83) == 0xC1


def test_gf2_inv_roundtrip():
    """对每个非零字节 a, a * a^{-1} == 1。"""
    for a in range(1, 256):
        inv = gf2_inv(a)
        assert gf2_mul(a, inv) == 1


def test_gf2_inv_zero():
    """0 的逆约定为 0 (AES SubBytes 特殊约定)。"""
    assert gf2_inv(0) == 0


# ----- S 盒正确性 (FIPS 197 标准值) -----

def test_sbox_known_values():
    assert SBOX[0x00] == 0x63
    assert SBOX[0x01] == 0x7C
    assert SBOX[0x53] == 0xED
    assert SBOX[0xFF] == 0x16


def test_sbox_inverse():
    """S 盒和逆 S 盒互逆。"""
    for i in range(256):
        assert INV_SBOX[SBOX[i]] == i
        assert SBOX[INV_SBOX[i]] == i


# ----- 密钥扩展 (FIPS 197 Appendix A.1) -----

def test_key_expansion_known_value():
    """FIPS 197 A.1 使用密钥 2b7e1516...。轮密钥 0 应等于原密钥。"""
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    rks = key_expansion(key)
    assert len(rks) == 11
    assert rks[0] == key
    # 轮密钥 10 (FIPS 197 A.1 末尾): d014f9a8 c9ee2589 e13f0cc8 b6630ca6
    assert rks[10] == bytes.fromhex("d014f9a8c9ee2589e13f0cc8b6630ca6")


# ----- AES-128 分组加密 (FIPS 197 Appendix B) -----

def test_aes_block_fips197_appendix_b():
    """FIPS 197 Appendix B 标准向量。"""
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    plaintext = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
    expected = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")
    assert encrypt_block(plaintext, key) == expected


def test_aes_block_fips197_appendix_c():
    """FIPS 197 Appendix C.1 (AES-128) 标准向量。"""
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    expected = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    assert encrypt_block(plaintext, key) == expected


def test_aes_decrypt_roundtrip():
    """加密后解密应得到原文。"""
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    plaintext = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
    cipher = encrypt_block(plaintext, key)
    assert decrypt_block(cipher, key) == plaintext


def test_aes_class_interface():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    aes = AES(key)
    assert aes.encrypt(plaintext) == bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    assert aes.decrypt(aes.encrypt(plaintext)) == plaintext


def test_aes_invalid_key_length():
    with pytest.raises(ValueError):
        AES(b"\x00" * 15)
    with pytest.raises(ValueError):
        encrypt_block(b"\x00" * 16, b"\x00" * 24)


# ----- PKCS#7 填充 -----

def test_pkcs7_pad_short():
    """5 字节输入应填充到 16 字节, 末尾 11 个 0x0B。"""
    data = b"hello"
    padded = pkcs7_pad(data)
    assert len(padded) == 16
    assert padded == b"hello" + bytes([0x0B] * 11)


def test_pkcs7_pad_full_block():
    """正好 16 字节也应追加 16 字节填充。"""
    data = b"a" * 16
    padded = pkcs7_pad(data)
    assert len(padded) == 32
    assert padded[16:] == bytes([0x10] * 16)


def test_pkcs7_unpad_roundtrip():
    for length in [0, 1, 15, 16, 17, 31, 32, 100]:
        data = bytes(range(length % 256)) * (length // 256 + 1)
        data = data[:length]
        assert pkcs7_unpad(pkcs7_pad(data)) == data


def test_pkcs7_unpad_invalid():
    with pytest.raises(ValueError):
        pkcs7_unpad(b"")
    with pytest.raises(ValueError):
        # 末尾不是有效的填充字节
        pkcs7_unpad(b"a" * 15 + b"\x00")


# ----- ECB 模式 -----

def test_ecb_roundtrip():
    key = b"YELLOW SUBMARINE"
    for msg in [b"", b"a", b"a" * 16, b"The quick brown fox jumps over the lazy dog"]:
        ct = ecb_encrypt(msg, key)
        assert ecb_decrypt(ct, key) == msg


def test_ecb_deterministic():
    """ECB 同一明文加密应得相同密文 (这正是 ECB 不安全的原因)。"""
    key = b"YELLOW SUBMARINE"
    msg = b"identical block!" * 4
    ct = ecb_encrypt(msg, key)
    # 4 个相同明文块加密后应得 4 个相同密文块
    blocks = [ct[i:i + 16] for i in range(0, 64, 16)]
    assert blocks[0] == blocks[1] == blocks[2] == blocks[3]


# ----- CBC 模式 -----

def test_cbc_roundtrip():
    key = b"YELLOW SUBMARINE"
    for msg in [b"", b"x", b"x" * 16, b"The quick brown fox jumps over the lazy dog"]:
        iv, ct = cbc_encrypt(msg, key)
        assert cbc_decrypt(ct, key, iv) == msg


def test_cbc_random_iv():
    """两次加密同一明文 (随机 IV) 应得到不同密文。"""
    key = b"YELLOW SUBMARINE"
    msg = b"same plaintext"
    iv1, ct1 = cbc_encrypt(msg, key)
    iv2, ct2 = cbc_encrypt(msg, key)
    assert iv1 != iv2  # 概率上几乎不可能相同
    assert ct1 != ct2


def test_cbc_invalid_iv():
    with pytest.raises(ValueError):
        cbc_encrypt(b"data", b"YELLOW SUBMARINE", iv=b"short")
    with pytest.raises(ValueError):
        cbc_decrypt(b"\x00" * 16, b"YELLOW SUBMARINE", iv=b"short")
