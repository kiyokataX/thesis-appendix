"""
素域 F_p 上的元素。

仅依赖 utils.math_ops 中的扩展欧几里得算法与快速模幂，从零实现 +、-、*、/、** 等运算。
"""
from __future__ import annotations
from typing import Union

from src.utils.math_ops import mod_inverse, mod_pow


class FieldElement:
    """F_p 中的一个元素。所有运算结果自动模 p。

    重载魔法方法以让数学公式与 Python 代码尽可能一一对应：
        a + b, a - b, a * b, a / b, a ** n, -a 均按 F_p 上的运算返回新 FieldElement。
    """

    __slots__ = ("num", "prime")

    def __init__(self, num: int, prime: int):
        if not (0 <= num < prime):
            raise ValueError(f"num {num} 不在 [0, {prime}) 范围内")
        self.num = num
        self.prime = prime

    def __repr__(self) -> str:
        return f"FieldElement_{self.prime}({self.num})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, FieldElement):
            return NotImplemented
        return self.num == other.num and self.prime == other.prime

    def __hash__(self) -> int:
        return hash((self.num, self.prime))

    def _check(self, other: "FieldElement") -> None:
        if self.prime != other.prime:
            raise TypeError(
                f"运算双方在不同的域中: F_{self.prime} vs F_{other.prime}"
            )

    def __add__(self, other: "FieldElement") -> "FieldElement":
        self._check(other)
        return FieldElement((self.num + other.num) % self.prime, self.prime)

    def __sub__(self, other: "FieldElement") -> "FieldElement":
        self._check(other)
        return FieldElement((self.num - other.num) % self.prime, self.prime)

    def __mul__(self, other: Union["FieldElement", int]) -> "FieldElement":
        if isinstance(other, int):
            return FieldElement((self.num * other) % self.prime, self.prime)
        self._check(other)
        return FieldElement((self.num * other.num) % self.prime, self.prime)

    __rmul__ = __mul__

    def __pow__(self, exp: int) -> "FieldElement":
        # 处理负指数: a^{-n} = (a^{-1})^n
        # 由费马小定理: a^{p-1} = 1，所以 a^{-1} = a^{p-2}
        # 更一般地，把 exp 归约到模 p-1 (仅当 num != 0)
        if self.num == 0:
            if exp <= 0:
                raise ZeroDivisionError("0 的非正幂次未定义")
            return FieldElement(0, self.prime)
        n = exp % (self.prime - 1)
        return FieldElement(mod_pow(self.num, n, self.prime), self.prime)

    def __truediv__(self, other: "FieldElement") -> "FieldElement":
        self._check(other)
        if other.num == 0:
            raise ZeroDivisionError("不能除以零元素")
        inv = mod_inverse(other.num, self.prime)
        return FieldElement((self.num * inv) % self.prime, self.prime)

    def __neg__(self) -> "FieldElement":
        return FieldElement((-self.num) % self.prime, self.prime)


if __name__ == "__main__":
    print("== FieldElement 自测 ==")
    a = FieldElement(7, 19)
    b = FieldElement(11, 19)
    print(f"a = {a}, b = {b}")
    print(f"a + b = {a + b}  # 期望 (7+11) mod 19 = 18")
    print(f"a - b = {a - b}  # 期望 (7-11) mod 19 = 15")
    print(f"a * b = {a * b}  # 期望 (77) mod 19 = 1")
    print(f"a ** 3 = {a ** 3}  # 期望 (343) mod 19 = 1")
    print(f"a / b = {a / b}  # 期望 7 * 11^{{-1}} mod 19 = 7 * 7 mod 19 = 11")
