"""AES-128 CBC 文本加解密演示。

这是教学用途的 demo：为了展示完整往返过程，会打印随机密钥、IV 和密文。
真实系统不应打印或记录密钥，也应优先使用成熟库提供的认证加密模式。
"""
from __future__ import annotations

import argparse
import secrets

from src.aes import cbc_decrypt, cbc_encrypt


DEFAULT_TEXT = "你好，AES-128！这是一个使用自写代码完成的 CBC 加解密演示。"


def run_demo(text: str = DEFAULT_TEXT) -> None:
    key = secrets.token_bytes(16)
    plaintext = text.encode("utf-8")

    iv, ciphertext = cbc_encrypt(plaintext, key)
    recovered = cbc_decrypt(ciphertext, key, iv).decode("utf-8")

    print("=== AES-128 CBC text demo ===")
    print(f"Plaintext:  {text}")
    print(f"Key(hex):   {key.hex()}")
    print(f"IV(hex):    {iv.hex()}")
    print(f"Cipher(hex): {ciphertext.hex()}")
    print(f"Recovered:  {recovered}")


def main() -> int:
    parser = argparse.ArgumentParser(description="AES-128 CBC 文本加解密演示")
    parser.add_argument("text", nargs="?", default=DEFAULT_TEXT, help="要加密的 UTF-8 文本")
    args = parser.parse_args()
    run_demo(args.text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
