"""
比特币真实交易 ECDSA 签名验证 (论文第 8.2 节实验)。

本脚本演示三个层次的验证, 由浅入深证明本文 secp256k1 + ECDSA 实现的工业级正确性:

    Level 1 (本地自测): 生成密钥对 -> 签名 -> 验签 / 篡改测试
    Level 2 (跨库验证): 若安装了 cryptography 库, 用其签名后由本文 ECDSA 验签 (反之亦然)
    Level 3 (真实 BTC tx): 抓取一笔 P2PKH 交易, 用本文实现重构 sighash 并验证签名

用法:
    cd crypto_thesis
    python -m experiments.btc_verify_demo                 # 仅 Level 1 + Level 2
    python -m experiments.btc_verify_demo --txid <hex>    # 三层都跑
"""
from __future__ import annotations
import argparse
import hashlib
import logging
import secrets
import sys
from typing import Tuple

from src.ecc import ecdsa
from src.ecc.curve import Point
from src.ecc.secp256k1 import SECP256K1


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------
# Level 1: 本地自测
# ---------------------------------------------------------------------

def level1_self_test() -> None:
    print("\n" + "=" * 60)
    print("Level 1: 本地自测 (生成密钥 -> 签名 -> 验签)")
    print("=" * 60)
    d = secrets.randbelow(SECP256K1.n - 1) + 1
    Q = ecdsa.public_key(d)
    msg = b"This thesis verifies its ECDSA on real Bitcoin signatures."

    sig = ecdsa.sign(d, msg)
    print(f"私钥 d (hex前24): {hex(d)[:26]}...")
    print(f"公钥 Q.x (hex):   {hex(Q.x)[:26]}...")
    print(f"签名 r (hex):     {hex(sig[0])[:26]}...")
    print(f"签名 s (hex):     {hex(sig[1])[:26]}...")

    assert ecdsa.verify(Q, msg, sig), "合法签名应通过"
    print("[OK] 合法签名验签通过")

    tampered = msg + b"\x00"
    assert not ecdsa.verify(Q, tampered, sig), "篡改后应失败"
    print("[OK] 篡改消息验签如预期失败")


# ---------------------------------------------------------------------
# Level 2: 跨库验证 (与 cryptography 库相互验证)
# ---------------------------------------------------------------------

def level2_cross_lib() -> None:
    print("\n" + "=" * 60)
    print("Level 2: 跨库验证 (本文 ECDSA <-> cryptography 库)")
    print("=" * 60)
    try:
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric.utils import (
            encode_dss_signature, decode_dss_signature,
        )
    except ImportError:
        print("[SKIP] 未安装 `cryptography` 库, 跳过 Level 2")
        print("   pip install cryptography 后可启用本环节")
        return

    # 用 cryptography 生成 secp256k1 密钥
    priv = ec.generate_private_key(ec.SECP256K1())
    d = priv.private_numbers().private_value
    pub_numbers = priv.public_key().public_numbers()
    Q = Point(pub_numbers.x, pub_numbers.y, SECP256K1)

    msg = b"Cross-library validation message"

    # cryptography 签名 -> 本文验签
    sig_der = priv.sign(msg, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(sig_der)
    valid = ecdsa.verify(Q, msg, (r, s))
    print(f"  cryptography 签名 -> 本文验签: {valid}")
    assert valid

    # 本文签名 -> cryptography 验签
    r2, s2 = ecdsa.sign(d, msg)
    sig_der2 = encode_dss_signature(r2, s2)
    try:
        priv.public_key().verify(sig_der2, msg, ec.ECDSA(hashes.SHA256()))
        valid2 = True
    except Exception:
        valid2 = False
    print(f"  本文签名 -> cryptography 验签: {valid2}")
    assert valid2

    print("[OK] 双向跨库验证通过 - 本文 secp256k1 + ECDSA 与工业实现等价")


# ---------------------------------------------------------------------
# Level 3: 真实比特币交易 (P2PKH legacy)
# ---------------------------------------------------------------------

def _h160(data: bytes) -> bytes:
    """RIPEMD160(SHA256(data)) - 比特币地址哈希。"""
    sha = hashlib.sha256(data).digest()
    try:
        return hashlib.new("ripemd160", sha).digest()
    except Exception as e:
        raise RuntimeError(
            "本机 hashlib 不支持 ripemd160 (OpenSSL 3.x 默认禁用)。"
            "请改用 pip install pycryptodome 替代实现。"
        ) from e


def _read_varint(data: bytes, off: int) -> tuple[int, int]:
    """读取比特币 VarInt, 返回 (值, 新偏移)。"""
    b = data[off]
    if b < 0xFD:
        return b, off + 1
    if b == 0xFD:
        return int.from_bytes(data[off + 1:off + 3], "little"), off + 3
    if b == 0xFE:
        return int.from_bytes(data[off + 1:off + 5], "little"), off + 5
    return int.from_bytes(data[off + 1:off + 9], "little"), off + 9


def _parse_tx(raw: bytes) -> dict:
    """解析比特币 legacy 交易 (不支持 SegWit)。"""
    off = 0
    version = int.from_bytes(raw[off:off + 4], "little")
    off += 4
    n_in, off = _read_varint(raw, off)
    inputs = []
    for _ in range(n_in):
        prev_txid = raw[off:off + 32][::-1]  # 内部以小端存储
        off += 32
        prev_idx = int.from_bytes(raw[off:off + 4], "little")
        off += 4
        script_len, off = _read_varint(raw, off)
        script_sig = raw[off:off + script_len]
        off += script_len
        seq = int.from_bytes(raw[off:off + 4], "little")
        off += 4
        inputs.append({
            "prev_txid": prev_txid.hex(),
            "prev_idx": prev_idx,
            "script_sig": script_sig,
            "sequence": seq,
        })
    n_out, off = _read_varint(raw, off)
    outputs = []
    for _ in range(n_out):
        value = int.from_bytes(raw[off:off + 8], "little")
        off += 8
        script_len, off = _read_varint(raw, off)
        script_pubkey = raw[off:off + script_len]
        off += script_len
        outputs.append({"value": value, "script_pubkey": script_pubkey})
    locktime = int.from_bytes(raw[off:off + 4], "little")
    off += 4
    return {
        "version": version,
        "inputs": inputs,
        "outputs": outputs,
        "locktime": locktime,
    }


def _serialize_varint(x: int) -> bytes:
    if x < 0xFD:
        return bytes([x])
    if x <= 0xFFFF:
        return b"\xFD" + x.to_bytes(2, "little")
    if x <= 0xFFFFFFFF:
        return b"\xFE" + x.to_bytes(4, "little")
    return b"\xFF" + x.to_bytes(8, "little")


def _build_p2pkh_preimage(tx: dict, input_idx: int, prev_script_pubkey: bytes) -> bytes:
    """重构 P2PKH 输入的签名预映像 (SIGHASH_ALL)。"""
    out = b""
    out += tx["version"].to_bytes(4, "little")
    out += _serialize_varint(len(tx["inputs"]))
    for i, inp in enumerate(tx["inputs"]):
        out += bytes.fromhex(inp["prev_txid"])[::-1]
        out += inp["prev_idx"].to_bytes(4, "little")
        if i == input_idx:
            out += _serialize_varint(len(prev_script_pubkey))
            out += prev_script_pubkey
        else:
            out += b"\x00"
        out += inp["sequence"].to_bytes(4, "little")
    out += _serialize_varint(len(tx["outputs"]))
    for o in tx["outputs"]:
        out += o["value"].to_bytes(8, "little")
        out += _serialize_varint(len(o["script_pubkey"]))
        out += o["script_pubkey"]
    out += tx["locktime"].to_bytes(4, "little")
    out += b"\x01\x00\x00\x00"  # SIGHASH_ALL = 1, 4 字节 LE
    return out


def _parse_p2pkh_scriptsig(script_sig: bytes) -> Tuple[Tuple[int, int], Point]:
    """从 P2PKH scriptSig 提取 (r, s) 与公钥点。

    格式: <push_sig_len> <DER_sig + sighash_type> <push_pubkey_len> <SEC_pubkey>
    """
    off = 0
    sig_len = script_sig[off]
    off += 1
    der_sig = script_sig[off:off + sig_len - 1]  # 末尾 1 字节是 sighash type
    off += sig_len
    pub_len = script_sig[off]
    off += 1
    sec_pub = script_sig[off:off + pub_len]

    # 解析 DER 签名 -> (r, s)
    assert der_sig[0] == 0x30
    body = der_sig[2:]  # 跳过 0x30 + total_len
    assert body[0] == 0x02
    rl = body[1]
    r = int.from_bytes(body[2:2 + rl], "big")
    body = body[2 + rl:]
    assert body[0] == 0x02
    sl = body[1]
    s = int.from_bytes(body[2:2 + sl], "big")

    # 解析 SEC 公钥 -> Point
    if sec_pub[0] == 0x04:
        x = int.from_bytes(sec_pub[1:33], "big")
        y = int.from_bytes(sec_pub[33:65], "big")
        Q = Point(x, y, SECP256K1)
    elif sec_pub[0] in (0x02, 0x03):
        x = int.from_bytes(sec_pub[1:33], "big")
        rhs = (pow(x, 3, SECP256K1.p) + SECP256K1.b) % SECP256K1.p
        y = pow(rhs, (SECP256K1.p + 1) // 4, SECP256K1.p)
        if (y % 2 == 0) != (sec_pub[0] == 0x02):
            y = SECP256K1.p - y
        Q = Point(x, y, SECP256K1)
    else:
        raise ValueError(f"未知 SEC 前缀 {sec_pub[0]:#x}")
    return (r, s), Q


def level3_real_btc(txid: str) -> None:
    print("\n" + "=" * 60)
    print(f"Level 3: 真实比特币交易验签 (txid={txid[:16]}...)")
    print("=" * 60)
    try:
        import requests
    except ImportError:
        print("[SKIP] 未安装 requests, 跳过 Level 3 (pip install requests)")
        return

    url = f"https://blockstream.info/api/tx/{txid}/hex"
    log.info(f"GET {url}")
    try:
        r = requests.get(url, timeout=30)
        r.raise_for_status()
    except Exception as e:
        print(f"[FAIL] 抓取交易失败: {e}")
        return
    raw = bytes.fromhex(r.text.strip())
    tx = _parse_tx(raw)
    print(f"version={tx['version']} inputs={len(tx['inputs'])} outputs={len(tx['outputs'])}")

    all_pass = True
    for i, inp in enumerate(tx["inputs"]):
        if not inp["script_sig"]:
            print(f"  input[{i}]: 无 scriptSig (可能是 SegWit/coinbase), 跳过")
            continue
        try:
            (r_, s_), Q = _parse_p2pkh_scriptsig(inp["script_sig"])
        except Exception as e:
            print(f"  input[{i}]: scriptSig 解析失败 ({e}), 跳过")
            continue
        # 重构 prev scriptPubKey: 76a914 <h160(pubkey)> 88ac
        sec_pub = b"\x04" + Q.x.to_bytes(32, "big") + Q.y.to_bytes(32, "big")
        # 注: 实际 BTC 多用压缩公钥, 我们也尝试压缩形式
        sec_pub_compressed = (
            b"\x02" if Q.y % 2 == 0 else b"\x03"
        ) + Q.x.to_bytes(32, "big")
        for sec in (sec_pub_compressed, sec_pub):
            try:
                h = _h160(sec)
            except RuntimeError as e:
                print(f"  [FAIL] {e}")
                return
            prev_script = b"\x76\xa9\x14" + h + b"\x88\xac"
            preimage = _build_p2pkh_preimage(tx, i, prev_script)
            z_bytes = hashlib.sha256(hashlib.sha256(preimage).digest()).digest()
            z = int.from_bytes(z_bytes, "big") % SECP256K1.n
            ok = ecdsa.verify_digest(Q, z, (r_, s_), SECP256K1)
            if ok:
                print(f"  [OK] input[{i}] 签名验证通过 (公钥形式: "
                      f"{'compressed' if sec is sec_pub_compressed else 'uncompressed'})")
                break
        else:
            print(f"  [FAIL] input[{i}] 签名验证失败 (两种公钥形式都试过)")
            all_pass = False
    if all_pass:
        print("\n[OK] 所有可解析的 P2PKH 输入签名均通过本文 secp256k1 + ECDSA 验证")


# ---------------------------------------------------------------------
def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--txid", help="(可选) 一笔比特币 P2PKH legacy 交易的 txid")
    args = ap.parse_args()

    level1_self_test()
    level2_cross_lib()
    if args.txid:
        level3_real_btc(args.txid)
    else:
        print("\n[INFO] 跳过 Level 3。如需运行真实 BTC 验签, 请加 --txid <hex> 参数")
        print("   推荐使用一笔较新的 P2PKH 交易 (输入 scriptSig 非空)")


if __name__ == "__main__":
    main()
