"""
椭圆曲线 y^2 = x^3 + a*x + b (在有限域 F_p 上) 的点群运算。

使用仿射坐标。性能不及雅可比坐标，但与论文中的代数公式一一对应，便于阅读与验证。
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, Union

from src.utils.math_ops import mod_inverse


@dataclass(frozen=True)
class Curve:
    """椭圆曲线域参数。"""
    p: int   # 有限域特征
    a: int
    b: int
    Gx: int  # 基点 x 坐标
    Gy: int  # 基点 y 坐标
    n: int   # 基点的阶 (大素数)

    def __repr__(self) -> str:
        return f"Curve(p={hex(self.p)[:12]}..., a={self.a}, b={self.b})"


class Point:
    """椭圆曲线上的点。

    无穷远点 O 由 x = y = None 表示。其余点 (x, y) 必须满足曲线方程。
    """

    __slots__ = ("x", "y", "curve")

    def __init__(self, x: Optional[int], y: Optional[int], curve: Curve):
        self.curve = curve
        if x is None and y is None:
            self.x, self.y = None, None
            return
        if x is None or y is None:
            raise ValueError("x, y 必须同时为 None 或同时非 None")
        # 验证点在曲线上: y^2 ≡ x^3 + a*x + b (mod p)
        lhs = (y * y) % curve.p
        rhs = (x * x * x + curve.a * x + curve.b) % curve.p
        if lhs != rhs:
            raise ValueError(f"点 ({hex(x)[:10]}..., {hex(y)[:10]}...) 不在曲线上")
        self.x, self.y = x % curve.p, y % curve.p

    @classmethod
    def infinity(cls, curve: Curve) -> "Point":
        return cls(None, None, curve)

    def is_infinity(self) -> bool:
        return self.x is None and self.y is None

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Point):
            return NotImplemented
        return self.x == other.x and self.y == other.y and self.curve == other.curve

    def __hash__(self) -> int:
        return hash((self.x, self.y, self.curve.p, self.curve.a, self.curve.b))

    def __repr__(self) -> str:
        if self.is_infinity():
            return "Point(O)"
        return f"Point({hex(self.x)[:10]}..., {hex(self.y)[:10]}...)"

    def __neg__(self) -> "Point":
        if self.is_infinity():
            return self
        return Point(self.x, (-self.y) % self.curve.p, self.curve)

    def __add__(self, other: "Point") -> "Point":
        if self.curve != other.curve:
            raise TypeError("两点不在同一曲线上")
        # 处理无穷远点
        if self.is_infinity():
            return other
        if other.is_infinity():
            return self
        # P + (-P) = O
        if self.x == other.x and (self.y + other.y) % self.curve.p == 0:
            return Point.infinity(self.curve)

        p = self.curve.p
        if self == other:
            # 倍点 (切线斜率)
            lam_num = (3 * self.x * self.x + self.curve.a) % p
            lam_den = (2 * self.y) % p
        else:
            # 不同点 (割线斜率)
            lam_num = (other.y - self.y) % p
            lam_den = (other.x - self.x) % p
        lam = (lam_num * mod_inverse(lam_den, p)) % p
        x3 = (lam * lam - self.x - other.x) % p
        y3 = (lam * (self.x - x3) - self.y) % p
        return Point(x3, y3, self.curve)

    def __rmul__(self, k: int) -> "Point":
        """标量乘法 k * P 使用 Double-and-Add 算法 (O(log k) 群运算)。"""
        if not isinstance(k, int):
            return NotImplemented
        # 归约到 [0, n)
        k %= self.curve.n
        if k == 0 or self.is_infinity():
            return Point.infinity(self.curve)
        result = Point.infinity(self.curve)
        addend = self
        while k > 0:
            if k & 1:
                result = result + addend
            addend = addend + addend
            k >>= 1
        return result

    def __mul__(self, k: int) -> "Point":
        return self.__rmul__(k)
