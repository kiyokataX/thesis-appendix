# Public-Key Cryptography from Scratch

Pure-Python implementations of the major public-key cryptosystems, built directly from their mathematical definitions with **no third-party crypto libraries**, and checked end-to-end against real Bitcoin transactions.

This is the companion code for my undergraduate thesis in Mathematics and Applied Mathematics (University of Shanghai for Science and Technology, 2026).

[中文说明 / Chinese README](README.zh.md)

## Highlights

- **Verified on real Bitcoin data.** Re-implements legacy P2PKH sighash reconstruction and checks every input of the 2010 *Bitcoin Pizza Day* transaction (`a1075db5…`, 10,000 BTC for two pizzas). All 131 input signatures verify with this project's own secp256k1 + ECDSA.
- **Cross-checked against OpenSSL.** Signatures produced here verify under the `cryptography` library (OpenSSL backend), and vice versa.
- **From first principles.** Extended GCD, Miller–Rabin, finite fields, RSA, Diffie–Hellman, ElGamal, DSA, elliptic-curve arithmetic, ECDSA, Schnorr and ECIES are all written from scratch.
- **Readable by design.** The code mirrors the algebra in the thesis, so it can be used as study material.
- **Tested.** 80+ pytest unit tests across all modules.

## What's inside

| Module | Contents |
|---|---|
| `src/utils/` | Modular arithmetic, extended Euclid, modular inverse, Miller–Rabin, prime generation, CRT |
| `src/fields/` | Elements of F_p and GF(2^8) |
| `src/classical/` | Shift and affine ciphers |
| `src/aes/` | AES-128, CBC mode, PKCS#7 padding |
| `src/rsa/` | Key generation, textbook RSA, OAEP, PSS, CRT-accelerated decryption |
| `src/dlp/` | Diffie–Hellman, ElGamal, DSA with RFC 6979 deterministic nonces |
| `src/ecc/` | Curve arithmetic, secp256k1, ECDSA (RFC 6979), Schnorr, ECIES |
| `src/blockchain/` | Accounts, signed transactions, Merkle trees, proof-of-work, chain validation |
| `experiments/` | End-to-end experiments from Chapter 8 of the thesis |
| `tests/` | pytest suite. Also the best place to see usage examples |

## Quick start

Requires Python 3.10+.

```bash
git clone https://github.com/kiyokataX/thesis-appendix.git
cd thesis-appendix
python -m pip install -r requirements.txt

python -m pytest -q                       # run the test suite
python -m experiments.toy_chain_demo      # toy blockchain: mining, validation, tamper detection
python -m experiments.btc_verify_demo     # ECDSA self-test + cross-library check

# Verify every input of the Pizza Day transaction (needs internet access)
python -m experiments.btc_verify_demo --txid a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d
```

`python main.py` lists all demos. Program output and code comments are mostly in Chinese.

## How the Bitcoin verification works

1. Fetch the raw transaction hex and parse it (version, inputs, outputs, locktime).
2. For each input, extract the DER-encoded signature `(r, s)` and SEC public key from `scriptSig`.
3. Rebuild the previous output's `scriptPubKey` from `HASH160(pubkey)`, trying both compressed and uncompressed key encodings.
4. Reconstruct the `SIGHASH_ALL` preimage and compute `z = SHA256(SHA256(preimage))`.
5. Run this project's `ecdsa.verify_digest(Q, z, (r, s))`.

The verification shows that this implementation agrees with Bitcoin's on real signatures. It is a correctness check, not a security claim (see below).

## Limitations

This is teaching code. It favours readability over performance and **must not be used in production**:

- Not constant-time, so it leaks timing side channels.
- No blinding or other side-channel countermeasures.
- ECC uses affine coordinates rather than Jacobian coordinates, which makes it much slower than real implementations.
- RSA uses CRT for decryption only; signing does not use it.
- ECIES is simplified (XOR keystream + HMAC rather than AES-GCM).
- Schnorr is the textbook scheme, not a full BIP-340 implementation.

For real systems, use audited libraries such as OpenSSL, libsecp256k1 or BoringSSL.

## Thesis chapter map

| Chapter | Modules |
|---|---|
| 2. Mathematical foundations | `src/utils/`, `src/fields/` |
| 3. Classical and symmetric ciphers | `src/classical/`, `src/aes/` |
| 5. RSA | `src/rsa/` |
| 6. Discrete-logarithm cryptosystems | `src/dlp/` |
| 7. Elliptic-curve cryptography and ECDSA | `src/ecc/` |
| 8. Blockchain applications and experiments | `src/blockchain/`, `experiments/` |

## License

MIT. See [LICENSE](LICENSE).
