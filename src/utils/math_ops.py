"""
密码学基础数学运算

包含: 最大公约数 (GCD)、扩展欧几里得算法 (EEA)、模逆元、快速模幂、
Miller-Rabin 概率素性检测、随机大素数生成、中国剩余定理 (CRT) 合并。

所有函数面向"从零实现"的论文需求设计，仅使用 Python 内置任意精度整数与
标准库 secrets，不依赖任何第三方密码学库。
"""
from __future__ import annotations
import secrets
from typing import Tuple


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """扩展欧几里得算法 (迭代版本)。

    返回 (g, x, y) 使 a*x + b*y = g = gcd(a, b)。
    迭代版本相对教科书递归版本可避免大整数下的栈溢出。
    """
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t


def mod_inverse(a: int, m: int) -> int:
    """求 a 在模 m 下的乘法逆元。要求 gcd(a, m) = 1，否则抛出 ValueError。"""
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        raise ValueError(f"模逆元不存在: gcd({a}, {m}) = {g} != 1")
    return x % m


def mod_pow(base: int, exp: int, mod: int) -> int:
    """快速模幂 (Square-and-Multiply)，O(log exp) 次模乘。

    注: Python 内置 ``pow(base, exp, mod)`` 在 C 层执行同等优化且更快，
    生产代码应直接使用 pow。本函数保留作为论文中算法演示用。
    """
    if mod == 1:
        return 0
    if exp < 0:
        return mod_pow(mod_inverse(base, mod), -exp, mod)
    result = 1
    base %= mod
    while exp > 0:
        if exp & 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp >>= 1
    return result


# 用于快速排除小因子的预计算表
_SMALL_PRIMES = (
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
    59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
)


def miller_rabin(n: int, k: int = 40) -> bool:
    """Miller-Rabin 概率型素性检测。

    返回 True 表示 n "极可能" 是素数 (单轮误判率 ≤ 1/4，独立 k 轮则 ≤ 4^{-k})；
    返回 False 时 n 必为合数。取 k=40 满足 RSA 大素数生成的可靠性要求。
    """
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False

    # 写 n - 1 = 2^s * d (d 奇)
    s, d = 0, n - 1
    while d % 2 == 0:
        s += 1
        d //= 2

    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2  # a ∈ [2, n-2]
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        composite = True
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                composite = False
                break
        if composite:
            return False
    return True


def generate_prime(bit_length: int) -> int:
    """随机生成给定位长的素数。

    通过反复采样满足 (最高位为 1, 最低位为 1) 的奇数候选，再调用 Miller-Rabin 检验。
    """
    if bit_length < 16:
        raise ValueError("bit_length 必须 ≥ 16")
    while True:
        candidate = secrets.randbits(bit_length) | (1 << (bit_length - 1)) | 1
        if miller_rabin(candidate):
            return candidate


def crt_combine(a1: int, m1: int, a2: int, m2: int) -> int:
    """中国剩余定理: 求满足 x ≡ a1 (mod m1), x ≡ a2 (mod m2) 的最小非负 x。

    要求 gcd(m1, m2) = 1，否则抛出 ValueError。
    """
    g, _, _ = extended_gcd(m1, m2)
    if g != 1:
        raise ValueError("m1 与 m2 不互素，CRT 不适用")
    M = m1 * m2
    return (a1 * m2 * mod_inverse(m2, m1) + a2 * m1 * mod_inverse(m1, m2)) % M


if __name__ == "__main__":
    print("=" * 50)
    print("math_ops 自测")
    print("=" * 50)
    print(f"extended_gcd(7, 26) = {extended_gcd(7, 26)}  # 期望 (1, -11, 3)")
    print(f"mod_inverse(7, 26) = {mod_inverse(7, 26)}  # 期望 15")
    print(f"mod_pow(2, 10, 1000) = {mod_pow(2, 10, 1000)}  # 期望 24")
    print(f"miller_rabin(101) = {miller_rabin(101)}  # 期望 True")
    print(f"miller_rabin(100) = {miller_rabin(100)}  # 期望 False")
    print(f"crt_combine(2, 3, 3, 5) = {crt_combine(2, 3, 3, 5)}  # 期望 8 (mod 15)")
    p = generate_prime(64)
    print(f"generate_prime(64) = {p} (Miller-Rabin: {miller_rabin(p)})")
