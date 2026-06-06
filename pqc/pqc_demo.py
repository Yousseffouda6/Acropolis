#!/usr/bin/env python3
"""Acropolis — Phase 7: a runnable post-quantum cryptography demo.

What this script demonstrates
-----------------------------
The two general-purpose post-quantum standards NIST finalized in 2024 — both
developed by IBM researchers with academic and industry partners — in action,
via the Open Quantum Safe project's `oqs` (liboqs-python) bindings:

  1. ML-KEM-768  (FIPS 203, formerly CRYSTALS-Kyber) — a Key Encapsulation
     Mechanism. Alice publishes a public key; Bob *encapsulates* a fresh shared
     secret against it and sends back a ciphertext; Alice *decapsulates* that
     ciphertext to recover the identical secret. This is the quantum-resistant
     replacement for classical (RSA / Diffie-Hellman) key exchange.

  2. ML-DSA-65   (FIPS 204, formerly CRYSTALS-Dilithium) — a digital signature
     scheme. A message is signed with a private key and verified with the public
     key; tampering with a single byte makes verification fail.

  3. A size comparison: post-quantum keys, ciphertexts and signatures are larger
     than their classical counterparts (here, an RSA-3072 public key). The table
     makes that trade-off — bigger artifacts in exchange for quantum resistance —
     visible at a glance.

How to run
----------
    pyenv shell 3.11.9
    pip install -r pqc/requirements.txt
    python pqc/pqc_demo.py

Notes
-----
- `liboqs-python` exposes the `oqs` module and builds/loads the liboqs C library
  on first import, so a C toolchain (cmake + compiler) must be available.
- The "ML-KEM-768" / "ML-DSA-65" mechanism names require a recent liboqs
  (>= 0.10.0); older builds used the names "Kyber768" / "Dilithium3".
"""

import sys

try:
    import oqs
except ImportError:
    sys.exit(
        "ERROR: the 'oqs' module is not installed.\n"
        "Install it with:  pip install -r pqc/requirements.txt\n"
        "(liboqs-python builds the liboqs C library on first install; you need "
        "cmake and a C compiler on PATH.)"
    )

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
except ImportError:
    sys.exit(
        "ERROR: the 'cryptography' package is not installed.\n"
        "Install it with:  pip install -r pqc/requirements.txt"
    )

KEM_ALG = "ML-KEM-768"
SIG_ALG = "ML-DSA-65"


def section(title):
    """Print a clear, framed section header."""
    print()
    print("=" * 70)
    print(title)
    print("=" * 70)


def check_mechanisms():
    """Fail early with a friendly message if the algorithms aren't compiled in."""
    if KEM_ALG not in oqs.get_enabled_kem_mechanisms():
        sys.exit(
            f"ERROR: '{KEM_ALG}' is not available in this liboqs build.\n"
            "Upgrade to liboqs >= 0.10.0 (older builds call it 'Kyber768')."
        )
    if SIG_ALG not in oqs.get_enabled_sig_mechanisms():
        sys.exit(
            f"ERROR: '{SIG_ALG}' is not available in this liboqs build.\n"
            "Upgrade to liboqs >= 0.10.0 (older builds call it 'Dilithium3')."
        )


def demo_kem():
    """ML-KEM-768 key encapsulation between Alice and Bob. Returns artifact sizes."""
    section(f"1. {KEM_ALG} — post-quantum key encapsulation (FIPS 203)")

    with oqs.KeyEncapsulation(KEM_ALG) as alice:
        public_key = alice.generate_keypair()
        print("  [Alice] generated an ML-KEM-768 keypair and published her public key.")
        print(f"          public key size : {len(public_key):>5,} bytes")

        # Bob encapsulates a fresh shared secret against Alice's public key.
        with oqs.KeyEncapsulation(KEM_ALG) as bob:
            ciphertext, bob_secret = bob.encap_secret(public_key)
        print("  [Bob]   encapsulated a shared secret against Alice's public key.")
        print(f"          ciphertext size : {len(ciphertext):>5,} bytes")

        # Alice decapsulates the ciphertext to recover the same shared secret.
        alice_secret = alice.decap_secret(ciphertext)
        print("  [Alice] decapsulated the ciphertext to recover the shared secret.")

    matches = alice_secret == bob_secret
    assert matches, "ML-KEM shared secrets DO NOT match — something is wrong!"
    print()
    print(f"  shared secret matches: {matches}")
    print(f"  shared secret length : {len(alice_secret)} bytes")

    return {
        "kem_public_key": len(public_key),
        "kem_ciphertext": len(ciphertext),
        "kem_shared_secret": len(alice_secret),
    }


def demo_signature():
    """ML-DSA-65 sign + verify, then a tampered-message verification. Returns sizes."""
    section(f"2. {SIG_ALG} — post-quantum digital signature (FIPS 204)")

    message = b"Acropolis: this note is authentic"

    with oqs.Signature(SIG_ALG) as signer:
        sig_public = signer.generate_keypair()
        signature = signer.sign(message)
    print(f"  [Signer]   signed message: {message!r}")
    print(f"             public key size: {len(sig_public):>5,} bytes")
    print(f"             signature size : {len(signature):>5,} bytes")

    # Verify the genuine signature against the original message.
    with oqs.Signature(SIG_ALG) as verifier:
        valid = verifier.verify(message, signature, sig_public)
    print(f"  [Verifier] signature valid: {valid}")
    assert valid, "Genuine signature failed to verify — something is wrong!"

    # Flip one byte of the message and verify again — it must now fail.
    tampered = bytearray(message)
    tampered[0] ^= 0xFF  # flip every bit of the first byte
    tampered = bytes(tampered)
    with oqs.Signature(SIG_ALG) as verifier:
        valid_tampered = verifier.verify(tampered, signature, sig_public)
    print()
    print(f"  Tampering with one byte: {message[:1]!r} -> {tampered[:1]!r}")
    print(f"  [Verifier] signature valid (tampered message): {valid_tampered}")
    assert not valid_tampered, "Tampered message verified — something is wrong!"

    return {
        "sig_public_key": len(sig_public),
        "sig_signature": len(signature),
    }


def measure_rsa_3072_public_key():
    """Generate an RSA-3072 keypair and return its serialized public-key size (bytes)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    public_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return len(public_der)


def print_comparison(sizes):
    """Print a classical-vs-post-quantum key-size table."""
    section("3. Key-size comparison — classical vs post-quantum")

    rows = [
        ("RSA-3072 (classical)", "public key", sizes["rsa_public_key"]),
        ("ML-KEM-768 (PQC)", "public key", sizes["kem_public_key"]),
        ("ML-KEM-768 (PQC)", "ciphertext", sizes["kem_ciphertext"]),
        ("ML-KEM-768 (PQC)", "shared secret", sizes["kem_shared_secret"]),
        ("ML-DSA-65 (PQC)", "public key", sizes["sig_public_key"]),
        ("ML-DSA-65 (PQC)", "signature", sizes["sig_signature"]),
    ]

    print(f"  {'Algorithm':<24}{'Artifact':<16}{'Size (bytes)':>14}")
    print("  " + "-" * 54)
    for algorithm, artifact, size in rows:
        print(f"  {algorithm:<24}{artifact:<16}{size:>14,}")

    factor = sizes["kem_public_key"] / sizes["rsa_public_key"]
    print()
    print(f"  ML-KEM-768 public keys are ~{factor:.1f}x larger than an RSA-3072")
    print("  public key — the size cost of resisting a cryptographically-relevant")
    print("  quantum computer. The derived shared secret stays a compact 32 bytes,")
    print("  ready to key a fast symmetric cipher (e.g. AES-256-GCM).")


def main():
    print("Acropolis — Phase 7: Post-Quantum Cryptography Demo")
    print("Open Quantum Safe (liboqs) · ML-KEM-768 (FIPS 203) · ML-DSA-65 (FIPS 204)")

    check_mechanisms()

    sizes = {}
    sizes.update(demo_kem())
    sizes.update(demo_signature())

    section("Measuring a classical RSA-3072 public key for comparison")
    sizes["rsa_public_key"] = measure_rsa_3072_public_key()
    print(f"  RSA-3072 public key (DER SubjectPublicKeyInfo): "
          f"{sizes['rsa_public_key']:,} bytes")

    print_comparison(sizes)

    print()
    print("Done — post-quantum key exchange and signatures verified end to end.")


if __name__ == "__main__":
    main()
