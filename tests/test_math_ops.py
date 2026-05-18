"""math_ops 单元测试。"""
import pytest
from src.utils.math_ops import (
    extended_gcd, mod_inverse, mod_pow, miller_rabin, generate_prime, crt_combine,
)


def test_extended_gcd_basic():
    g, x, y = extended_gcd(7, 26)
    assert g == 1
    assert 7 * x + 26 * y == 1


def test_extended_gcd_zero():
    g, x, y = extended_gcd(15, 0)
    assert g == 15
    assert x == 1 and y == 0


def test_mod_inverse():
    assert mod_inverse(7, 26) == 15
    assert (7 * 15) % 26 == 1


def test_mod_inverse_no_solution():
    with pytest.raises(ValueError):
        mod_inverse(4, 26)  # gcd = 2


def test_mod_pow():
    assert mod_pow(2, 10, 1000) == 24
    assert mod_pow(3, 100, 7) == pow(3, 100, 7)


def test_miller_rabin_known_primes():
    for p in [2, 3, 5, 7, 11, 13, 101, 7919, 104729]:
        assert miller_rabin(p), f"{p} 应被识别为素数"


def test_miller_rabin_known_composites():
    for n in [4, 6, 9, 15, 100, 561, 1105]:  # 包含 Carmichael 数
        assert not miller_rabin(n), f"{n} 应被识别为合数"


def test_generate_prime_bit_length():
    p = generate_prime(64)
    assert p.bit_length() == 64
    assert miller_rabin(p)


def test_crt_combine():
    # x ≡ 2 (mod 3), x ≡ 3 (mod 5) => x = 8
    assert crt_combine(2, 3, 3, 5) == 8
