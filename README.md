# Public-Key Cryptography from Scratch

> 上海理工大学数学与应用数学专业 2026 届本科毕业论文《公钥密码体制及其应用》的配套代码库。
>
> Companion code for the undergraduate thesis *Public-key Cryptosystems and Their Applications* (USST, 2026).

本项目从纯数学定义出发，独立实现了主流公钥密码算法的 Python 底层代码——不依赖任何第三方密码学库——并通过真实比特币交易验签与极简区块链原型完成端到端验证。

## 项目特点

- **从零实现**：核心数学与密码原语（GCD、Miller-Rabin、有限域、RSA、Diffie-Hellman、ElGamal、DSA、椭圆曲线、ECDSA、Schnorr、ECIES）均独立编码，不依赖 `cryptography`、`pycryptodome` 等成熟库
- **教学优先**：可读性高于性能，代数公式与代码对应直观，适合学习与教学
- **端到端验证**：含真实 BTC 交易验签（2010 披萨日 131 个 P2PKH 输入全验签通过）+ 极简区块链原型 demo
- **测试齐备**：约 50 项 pytest 单元测试，覆盖各模块；与 `cryptography` 库双向跨库互验通过
- **MIT License**：允许任何形式的学习、修改与再分发

## 目录结构

```
.
├── src/                核心算法实现
│   ├── utils/          模运算、扩展欧几里得、Miller-Rabin 等工具
│   ├── fields/         有限域 F_p 与 GF(2^8) 元素类
│   ├── classical/      古典密码（移位 / 仿射）
│   ├── aes/            AES-128、CBC、PKCS#7
│   ├── rsa/            RSA 密钥生成 / 加解密 / 签名 / OAEP / PSS / CRT 加速
│   ├── dlp/            Diffie-Hellman、ElGamal、DSA、RFC 6979 确定性签名
│   ├── ecc/            secp256k1、椭圆曲线点运算、ECDSA、Schnorr、ECIES
│   └── blockchain/     账户、签名交易、Merkle Tree、PoW、链式哈希
├── experiments/        论文第 8 章端到端实验
│   ├── btc_verify_demo.py   真实比特币交易 ECDSA 验签（三层验证）
│   ├── toy_chain_demo.py    极简区块链原型演示
│   └── aes_text_demo.py     AES-128 CBC 文本加解密演示
├── tests/              pytest 单元测试
├── main.py             项目入口（提供 chapter1 / blockchain / ecdsa 等子命令）
├── pyproject.toml      项目配置
├── requirements.txt    Python 依赖
└── setup.py            包安装配置
```

## 论文对照表

| 论文章节 | 对应模块 |
|---|---|
| 第 2 章 数学基础 | `src/utils/`, `src/fields/` |
| 第 3 章 古典密码与对称密码 | `src/classical/`, `src/aes/` |
| 第 5 章 RSA 密码体制 | `src/rsa/` |
| 第 6 章 离散对数公钥体制 | `src/dlp/` |
| 第 7 章 椭圆曲线密码体制与 ECDSA | `src/ecc/` |
| 第 8 章 区块链应用与实验 | `src/blockchain/`, `experiments/` |

## 快速开始

### 环境要求

- Python 3.10+ （3.11 推荐）
- Windows / macOS / Linux 均可

### 安装

```bash
git clone https://github.com/<your-username>/public-key-crypto-thesis.git
cd public-key-crypto-thesis
python -m pip install -r requirements.txt
```

### 运行单元测试

```bash
python -m pytest -vv
```

### 运行论文实验

```bash
# 极简区块链原型（含账户、签名交易、Merkle 树、PoW、整链验证、篡改检测）
python -m experiments.toy_chain_demo

# 比特币 ECDSA 验签三层验证
# Level 1+2: 本地自测 + 与 cryptography 库跨库互验
python -m experiments.btc_verify_demo

# Level 3: 真实 BTC 交易验签（需联网）
python -m experiments.btc_verify_demo --txid a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d
```

Windows 终端默认 GBK 编码可能导致中文输出乱码，运行前设置 UTF-8：

```powershell
$env:PYTHONIOENCODING = 'utf-8'
```

### 项目入口（可选）

```bash
python main.py              # 查看可用子命令
python main.py blockchain   # 等价于 experiments/toy_chain_demo
python main.py ecdsa        # 等价于 experiments/btc_verify_demo
```

## 实验亮点

### 真实比特币交易 ECDSA 验签

抓取 2010-05-22 的"披萨日"交易（`a1075db5...`，Laszlo Hanyecz 用 10000 BTC 购买两个披萨，全球第一次比特币实物交易），用本项目从零实现的 secp256k1 + ECDSA 独立验证其全部 131 个 P2PKH 输入签名 — **全部通过**。

证明本实现与比特币主网工业级实现在签名计算层面严格等价。

### 跨库互验

与 `cryptography` 库（OpenSSL backend）双向互验：
- 本项目签名 → `cryptography` 库验签 ✅
- `cryptography` 库签名 → 本项目验签 ✅

## 设计原则与局限

本项目以**算法可读性与数学对应性**为优先目标，不适用于生产环境：

- 未做恒定时间实现，存在时序侧信道
- 未做盲化、随机延迟等高级抗侧信道防护
- ECC 使用仿射坐标而非雅可比坐标，性能远低于工业实现
- RSA 签名暂未做 CRT 加速（仅解密做了 CRT）
- ECIES 为教学简化版（XOR keystream + HMAC，非 AES-GCM）
- Schnorr 实现为抽象版，非 BIP-340 完整实现

真实系统中的密码学功能请使用 OpenSSL、libsecp256k1、BoringSSL 等经过审计的成熟实现。

## 关于这篇论文

- **题目**：公钥密码体制及其应用 / *Public-key Cryptosystems and Their Applications*
- **作者**：饶曜涵
- **学校**：上海理工大学 理学院 数学与应用数学专业
- **导师**：吴宝丰
- **答辩**：2026-05

## License

MIT License — 详见 [LICENSE](LICENSE)。
