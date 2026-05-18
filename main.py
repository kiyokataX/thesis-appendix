"""毕业论文代码库的便捷入口。

这个项目主要是“算法库 + 测试 + 实验脚本”，不是一个单独的应用程序。
保留 main.py 是为了让直接运行 ``python main.py`` 时能看到项目地图，
而不是误以为某个小 demo 就是整个项目。
"""
from __future__ import annotations

import argparse
import subprocess
import sys

from src.classical.affine import AffineCipher
from src.utils.math_ops import extended_gcd


def euler_phi(m: int) -> tuple[list[int], int]:
    """返回 [0, m) 中所有与 m 互素的整数，以及欧拉函数 phi(m)。"""
    coprimes = [n for n in range(m) if extended_gcd(n, m)[0] == 1]
    return coprimes, len(coprimes)


def chapter1_demo() -> None:
    """运行原来的第 1 章习题小 demo。"""
    print("=== 第 1 章 demo：欧拉函数 ===")
    for m in [4, 5, 9, 26]:
        coprimes, phi = euler_phi(m)
        print(f"m={m}: coprimes={coprimes}, phi({m})={phi}")

    print("\n=== 第 1 章 demo：仿射密码解密 ===")
    cipher = AffineCipher(a=7, b=22)
    ciphertext = "falszztysyjzyjkywjrztyjztyynaryjkyswarztyegyyj"
    plaintext = cipher.decrypt(ciphertext)
    print(f"Ciphertext: {ciphertext}")
    print(f"Plaintext:  {plaintext.lower()}")


def run_module(module: str) -> int:
    """使用当前 Python 解释器运行项目内的模块。"""
    return subprocess.call([sys.executable, "-m", module])


def print_guide() -> None:
    print(
        """密码学毕业论文代码库

这个项目不是一个单独的 app，而是论文配套的算法库、测试和实验脚本。

常用命令：
  python -m pytest -vv                 运行所有测试
  python main.py chapter1              运行第 1 章小 demo
  python main.py aes "你好，AES"        运行 AES-128 CBC 文本加解密 demo
  python main.py blockchain            运行极简区块链实验
  python main.py ecdsa                 运行 ECDSA 自测和跨库验证

主要目录：
  src/          算法实现
  tests/        单元测试，也是用法示例
  experiments/  论文实验脚本
  studies/      学习和教材习题代码
"""
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="毕业论文代码库入口")
    parser.add_argument(
        "command",
        nargs="?",
        choices=["chapter1", "aes", "blockchain", "ecdsa"],
        help="可选：运行某个 demo 或实验",
    )
    parser.add_argument("args", nargs=argparse.REMAINDER, help="传递给 demo 的附加参数")
    args = parser.parse_args(argv)

    if args.command is None:
        print_guide()
        return 0
    if args.command == "chapter1":
        chapter1_demo()
        return 0
    if args.command == "aes":
        return subprocess.call([sys.executable, "-m", "experiments.aes_text_demo", *args.args])
    if args.command == "blockchain":
        return run_module("experiments.toy_chain_demo")
    if args.command == "ecdsa":
        return run_module("experiments.btc_verify_demo")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
