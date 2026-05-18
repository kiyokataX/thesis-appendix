"""
secp256k1 曲线参数 (比特币、以太坊等主流区块链使用)。

参数来源: SECG, "SEC 2: Recommended Elliptic Curve Domain Parameters", §2.4.1。
曲线方程: y^2 = x^3 + 7 (mod p), 即 a = 0, b = 7。
"""
from __future__ import annotations
from .curve import Curve, Point


SECP256K1 = Curve(
    p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    a=0,
    b=7,
    Gx=0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    Gy=0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
)


def base_point() -> Point:
    """secp256k1 的基点 G。"""
    return Point(SECP256K1.Gx, SECP256K1.Gy, SECP256K1)


if __name__ == "__main__":
    G = base_point()
    print(f"基点 G = {G}")
    print(f"n * G (应为无穷远点 O): {SECP256K1.n * G}")
    print(f"2G = {2 * G}")
    print(f"(n-1) * G == -G : {(SECP256K1.n - 1) * G == -G}")
