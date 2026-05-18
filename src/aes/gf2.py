"""
GF(2^8) 上的字节运算 (AES 使用)。

约化多项式 m(x) = x^8 + x^4 + x^3 + x + 1 (二进制 0x11B)。
元素以一个字节 (8 比特) 表示, 加法 = 按位异或, 乘法 = 多项式乘后再模 m(x)。
"""
from __future__ import annotations


def gf2_add(a: int, b: int) -> int:
    """GF(2^8) 加法 = 按位异或。"""
    return (a ^ b) & 0xFF


def gf2_mul(a: int, b: int) -> int:
    """GF(2^8) 乘法 (俄罗斯农民法 + 模约简)。"""
    result = 0
    a &= 0xFF
    b &= 0xFF
    for _ in range(8):
        if b & 1:
            result ^= a
        carry = a & 0x80
        a = (a << 1) & 0xFF
        if carry:
            a ^= 0x1B  # x^8 ≡ x^4 + x^3 + x + 1 (mod m(x))
        b >>= 1
    return result


def gf2_pow(a: int, n: int) -> int:
    """GF(2^8) 上的 a^n (Square-and-Multiply, 用于求 S 盒乘法逆 = a^254)。"""
    result = 1
    base = a & 0xFF
    while n > 0:
        if n & 1:
            result = gf2_mul(result, base)
        base = gf2_mul(base, base)
        n >>= 1
    return result


def gf2_inv(a: int) -> int:
    """GF(2^8) 中的乘法逆: a^{-1} = a^{254} (按 GF(2^8) 上的费马小定理)。

    约定 0 的"逆"为 0, 这是 AES SubBytes 的特殊约定 (并非真的逆元)。
    """
    if a == 0:
        return 0
    return gf2_pow(a, 254)


if __name__ == "__main__":
    # 论文 §2.3.2 中的具体例子: 0x57 * 0x83 = 0xC1
    a, b = 0x57, 0x83
    print(f"0x{a:02x} + 0x{b:02x} = 0x{gf2_add(a, b):02x}  (期望 0xD4)")
    print(f"0x{a:02x} * 0x{b:02x} = 0x{gf2_mul(a, b):02x}  (期望 0xC1)")
    print(f"0x53^{{-1}} = 0x{gf2_inv(0x53):02x}  (期望 0xCA)")
    # 验证 0x53 * 0xCA = 1
    print(f"0x53 * 0xCA = 0x{gf2_mul(0x53, 0xCA):02x}  (期望 0x01)")
