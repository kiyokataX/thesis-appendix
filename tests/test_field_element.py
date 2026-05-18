"""FieldElement 单元测试。"""
import pytest
from src.fields import FieldElement


P = 19  # 小素数, 便于手工核对


def test_constructor_range():
    with pytest.raises(ValueError):
        FieldElement(20, P)
    with pytest.raises(ValueError):
        FieldElement(-1, P)


def test_equality():
    assert FieldElement(7, P) == FieldElement(7, P)
    assert FieldElement(7, P) != FieldElement(8, P)


def test_add_sub():
    a = FieldElement(7, P)
    b = FieldElement(15, P)
    assert (a + b).num == (7 + 15) % P
    assert (a - b).num == (7 - 15) % P


def test_mul():
    a = FieldElement(7, P)
    b = FieldElement(11, P)
    # 7 * 11 = 77, 77 mod 19 = 1
    assert (a * b).num == 1


def test_pow_and_div():
    a = FieldElement(7, P)
    # a^{P-1} = 1 (费马小定理)
    assert (a ** (P - 1)).num == 1
    # a / a = 1
    assert (a / a).num == 1
    # a^{-1} via __pow__(-1)
    inv = a ** -1
    assert (a * inv).num == 1


def test_different_field_raises():
    a = FieldElement(7, 19)
    b = FieldElement(7, 23)
    with pytest.raises(TypeError):
        _ = a + b
