# Phase 7 — Post-Quantum Cryptography demo

A small, runnable demonstration of the two general-purpose NIST post-quantum
standards (finalized in 2024, developed by IBM researchers with academic and
industry partners), via the [Open Quantum Safe](https://openquantumsafe.org/)
project's `liboqs-python` bindings:

- **ML-KEM-768** (FIPS 203, formerly CRYSTALS-Kyber) — post-quantum **key
  encapsulation** (the replacement for RSA / Diffie-Hellman key exchange).
- **ML-DSA-65** (FIPS 204, formerly CRYSTALS-Dilithium) — post-quantum **digital
  signatures**.

[`pqc_demo.py`](./pqc_demo.py) runs an ML-KEM-768 key exchange, an ML-DSA-65
sign/verify (including a tampered-message rejection), and prints a size
comparison against a classical RSA-3072 public key. The full write-up — the
quantum threat model, "harvest now, decrypt later", and a crypto inventory of
the Acropolis lab — is in
[`../writeups/phase-7-pqc.md`](../writeups/phase-7-pqc.md).

---

## Run it (Docker — recommended)

Installing `liboqs-python` directly on the host tends to fail on Apple Silicon,
where an Anaconda Python and liboqs's own build-time architecture assumptions
collide while compiling the liboqs C library. A clean `python:3.12-slim`
container sidesteps that entirely.

**From the repository root**, start a container with the repo mounted at `/work`:

```bash
docker run --rm -it -v "$PWD":/work python:3.12-slim bash
```

Then, **inside the container**, install the toolchain and dependencies and run
the demo:

```bash
apt-get update && apt-get install -y cmake gcc git libssl-dev
pip install git+https://github.com/open-quantum-safe/liboqs-python.git cryptography
python /work/pqc/pqc_demo.py
```

The first `pip install` builds the liboqs C library from source (a minute or
two). The two dependencies are also captured in
[`requirements.txt`](./requirements.txt) if you prefer
`pip install -r /work/pqc/requirements.txt`.

---

## Expected output

```
======================================================================
1. ML-KEM-768 — post-quantum key encapsulation (FIPS 203)
======================================================================
  [Alice] generated an ML-KEM-768 keypair and published her public key.
          public key size : 1,184 bytes
  [Bob]   encapsulated a shared secret against Alice's public key.
          ciphertext size : 1,088 bytes
  [Alice] decapsulated the ciphertext to recover the shared secret.

  shared secret matches: True
  shared secret length : 32 bytes

======================================================================
2. ML-DSA-65 — post-quantum digital signature (FIPS 204)
======================================================================
  [Signer]   public key size: 1,952 bytes
             signature size : 3,309 bytes
  [Verifier] signature valid: True
  [Verifier] signature valid (tampered message): False

======================================================================
3. Key-size comparison — classical vs post-quantum
======================================================================
  Algorithm               Artifact         Size (bytes)   vs RSA-3072
  -------------------------------------------------------------------
  RSA-3072 (classical)    public key                422          1.0x
  ML-KEM-768 (PQC)        public key              1,184          2.8x
  ML-KEM-768 (PQC)        ciphertext              1,088          2.6x
  ML-KEM-768 (PQC)        shared secret              32          0.1x
  ML-DSA-65 (PQC)         public key              1,952          4.6x
  ML-DSA-65 (PQC)         signature               3,309          7.8x
```

The headline: post-quantum public keys and signatures run roughly **3–8x** the
size of an RSA-3072 public key — that size growth is the real migration cost.
The derived ML-KEM shared secret itself stays a compact 32 bytes.
