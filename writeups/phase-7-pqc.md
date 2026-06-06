# Phase 7 — Post-Quantum Cryptography: inventory the crypto before the quantum computer arrives

This is the lab's forward-looking module. There is no exploit to run and no flag
to capture — the adversary is a machine that does not exist yet. Phase 7 builds a
working demo of the two NIST post-quantum standards, measures what they actually
cost, and then does the unglamorous first step of any real migration:
**inventory every place Acropolis uses cryptography and classify each one as
quantum-safe or quantum-vulnerable.** The headline: symmetric crypto survives the
quantum era almost untouched; every asymmetric key exchange and signature in the
stack has to move — and the price of moving is measured in bytes on the wire.

> **Scope.** This module covers post-quantum *cryptography* (software). Quantum
> Key Distribution is a hardware/photonics discipline and is intentionally out of
> scope — discussed conceptually here, not implemented. The demo runs in a clean
> `python:3.12-slim` container (see [`../pqc/README.md`](../pqc/README.md)); no
> production system is modified.

---

## The engagement at a glance

| | |
| --- | --- |
| Goal | Demonstrate the NIST PQC standards and inventory Acropolis's crypto for migration |
| Key exchange | ML-KEM-768 (FIPS 203, ex-CRYSTALS-Kyber) — security level 3 |
| Signatures | ML-DSA-65 (FIPS 204, ex-CRYSTALS-Dilithium) — security level 3 |
| Tooling | Open Quantum Safe (`liboqs-python`) + `cryptography`, in `python:3.12-slim` |
| Headline | Symmetric crypto is fine (AES-256 stays safe); all asymmetric key exchange and signatures must migrate. PQC keys/sigs are 3–8x larger — the migration cost is bytes, not security |

---

## The quantum threat: what breaks, and what doesn't

A cryptographically-relevant quantum computer (CRQC) does not exist today. But two
quantum algorithms already define what it *will* break, and the asymmetry between
them is the entire story of post-quantum migration.

**Shor's algorithm — catastrophic for asymmetric crypto.** Shor's algorithm
factors large integers and solves the discrete-logarithm problem in *polynomial*
time. Every widely deployed public-key primitive rests on exactly those problems
being hard:

- **RSA** — security from integer factorisation → **broken**.
- **Diffie-Hellman / ECDH** key exchange — discrete log → **broken**.
- **ECDSA / EdDSA (Ed25519)** signatures — discrete log → **broken**.

A CRQC running Shor doesn't weaken these — it ends them. The key exchange that
protects a TLS session and the signatures that authenticate it both fall.

**Grover's algorithm — a mild dent in symmetric crypto.** Grover's algorithm
gives only a *quadratic* speedup on unstructured search, which halves the
effective security level of a symmetric primitive:

- **AES-128** → ~64-bit effective security → no longer comfortable.
- **AES-256** → ~128-bit effective security → **still safe**.
- **SHA-256** → ~128-bit collision resistance → **still safe**.

Grover is defeated by *doubling the key size* — which the world has largely
already done. AES-256 and SHA-384/512 walk into the quantum era essentially
intact.

**The conclusion that drives everything else:** the quantum threat is specifically
a threat to **asymmetric key exchange and digital signatures**, not to bulk
symmetric encryption. Migration effort goes where Shor bites.

---

## "Harvest now, decrypt later" — why this is urgent before any CRQC exists

The natural objection is "no quantum computer can break RSA today, so why migrate
now?" The answer is a passive attack that is already happening:

> An adversary captures encrypted traffic **today** and simply stores it. When a
> CRQC arrives — in 5, 10, or 15 years — they replay the stored key exchange
> through Shor's algorithm, recover the session keys, and decrypt the traffic
> retroactively.

Any data whose **confidentiality lifetime** outlasts the arrival of a CRQC is
*already* exposed, even though the machine that breaks it hasn't been built. Health
records, state secrets, financial data, long-lived credentials — the clock on all
of them started the moment they crossed the wire. This is why standards bodies
treat PQC migration as urgent now rather than a problem for the 2030s.

Signatures have a kinder timeline: you cannot *retroactively* forge a TLS handshake
or a code-signing event that already completed, so a future CRQC can't reach back
and fake past signatures. Signature migration still matters — for long-lived trust
anchors like root CAs and firmware-signing keys — but confidentiality (key
exchange) is the part that bleeds today.

---

## The standards: ML-KEM and ML-DSA

In August 2024, NIST finalised the first general-purpose post-quantum standards,
all based on the mathematics of structured lattices (Module-LWE) and all developed
by IBM researchers with academic and industry partners:

- **FIPS 203 — ML-KEM** (Module-Lattice Key Encapsulation Mechanism), from
  CRYSTALS-Kyber. The quantum-safe replacement for RSA/DH **key exchange**.
- **FIPS 204 — ML-DSA** (Module-Lattice Digital Signature Algorithm), from
  CRYSTALS-Dilithium. The quantum-safe replacement for ECDSA/EdDSA **signatures**.
- (FIPS 205 — SLH-DSA / SPHINCS+, a hash-based signature, is a conservative
  backup; out of scope here.)

A **KEM is not a key-agreement.** Where Diffie-Hellman has both sides contribute to
a shared value, ML-KEM is asymmetric in roles: one party publishes a public key;
the other **encapsulates** a freshly generated random secret against it, producing
a ciphertext; the first party **decapsulates** that ciphertext with its private key
to recover the identical secret. That shared secret then keys a fast symmetric
cipher (AES-256-GCM) for the actual data.

**Hybrid is how this ships in the real world.** Production TLS deployments
(Chrome, Cloudflare, OpenSSL 3.5+) don't switch to *pure* ML-KEM — they run
**hybrid** suites like **X25519MLKEM768**, concatenating a classical X25519
exchange with ML-KEM-768. The connection stays secure if **either** component
holds: classical X25519 covers the risk that a young PQC implementation has a flaw,
and ML-KEM covers the quantum threat to X25519. Hybrid is the pragmatic default for
the entire migration.

---

## The hands-on demo (with the real measured numbers)

[`pqc/pqc_demo.py`](../pqc/pqc_demo.py) exercises both standards through Open
Quantum Safe and measures every artifact. Numbers below are the actual output
against liboqs 0.15.0.

**ML-KEM-768 key encapsulation.** Alice generates a keypair; Bob encapsulates a
secret against her public key; Alice decapsulates the ciphertext. Both sides derive
the identical 32-byte secret:

| Artifact | Size |
| --- | --- |
| Public key | **1,184 B** |
| Ciphertext | **1,088 B** |
| Shared secret | **32 B** (matched on both sides ✓) |

**ML-DSA-65 signatures.** A message is signed and verified; then one byte of the
message is flipped and verification is run again:

| Artifact / check | Result |
| --- | --- |
| Public key | **1,952 B** |
| Signature | **3,309 B** |
| Verify genuine message | **True** |
| Verify tampered message (1 byte flipped) | **False** |

> **An integration-security note worth its own line.** `liboqs`' `verify()`
> **returns a boolean — it does not raise on a bad signature.** A tampered message
> yields `False`, not an exception. This is a classic real-world footgun: code
> written as `try: verify(...) except: reject()` — expecting failures to throw —
> will sail straight past the `try`, treat *every* signature as accepted, and
> silently verify forgeries. The demo checks the return value explicitly and never
> wraps `verify()` in `try/except`, which is the correct pattern.

**Size comparison vs classical RSA-3072.** The `cryptography` library generates an
RSA-3072 keypair; its serialized (DER `SubjectPublicKeyInfo`) public key is the
baseline:

| Algorithm | Artifact | Size (bytes) | vs RSA-3072 pubkey |
| --- | --- | ---: | ---: |
| RSA-3072 (classical) | public key | 422 | 1.0x |
| ML-KEM-768 (PQC) | public key | 1,184 | 2.8x |
| ML-KEM-768 (PQC) | ciphertext | 1,088 | 2.6x |
| ML-KEM-768 (PQC) | shared secret | 32 | 0.1x |
| ML-DSA-65 (PQC) | public key | 1,952 | 4.6x |
| ML-DSA-65 (PQC) | signature | 3,309 | 7.8x |

**The takeaway is the cost, not the security.** ML-KEM and ML-DSA *work* — the key
exchange agrees, the signatures verify, tampering is caught. What changes is
**size**: post-quantum public keys and signatures run roughly **3–8x** larger than
an RSA-3072 public key, with the ML-DSA-65 signature the worst at ~8x. That means
bigger TLS handshakes, bigger certificates, and more bytes on every connection —
the genuine engineering cost of migration. (The derived shared secret stays a tidy
32 bytes, because it only ever keys a symmetric cipher.)

---

## Crypto inventory of Acropolis — the realistic first migration step

You cannot migrate what you cannot see. Before changing a single algorithm, the
right first move is a **cryptographic inventory**: walk every component built across
Phases 1–5 and classify each use of crypto by primitive and quantum exposure.

| Component | Where it lives | Primitive | Quantum status | Action |
| --- | --- | --- | --- | --- |
| **Session cookie signing** | Flask `SECRET_KEY` → `itsdangerous` HMAC (Phase 1) | **HMAC-SHA — symmetric** | **Quantum-safe** (only Grover applies; HMAC is unaffected in practice) | None *for quantum*. But it is still **VULN #1** — the key is hardcoded in source, so sessions are forgeable offline today. Move it to a secret manager and rotate. |
| **nginx TLS** (front door) | reverse proxy added in Phase 5 | **hybrid X25519MLKEM768** (X25519 + ML-KEM-768) | **✅ Migrated to hybrid PQC** (TLS 1.3, OpenSSL 3.5.5) | **Done** — `ssl_ecdh_curve X25519MLKEM768:X25519`, verified on the wire (see *Migration performed* below). |
| **SSH access** | host + user keys (Phase 3) | **Ed25519 / RSA** | **Quantum-VULNERABLE** (Shor) | Adopt a PQC/hybrid SSH KEX (`mlkem768x25519-sha256` / `sntrup761x25519`). |
| **Wazuh dashboard TLS** | SIEM dashboard + indexer (Phase 4) | **RSA / ECDHE** TLS | **Quantum-VULNERABLE** (Shor) | Hybrid PQC TLS once the OpenSearch/dashboard stack supports it. |

The inventory makes the Shor/Grover split concrete: the **one symmetric** use in
the lab (the session HMAC) is quantum-safe — its problem is a *classical* planted
flaw, not a quantum one — while the **TLS/SSH handshakes** all rest on asymmetric
key exchange and sit squarely in Shor's path. The nginx front door has **already
been moved** off that path to hybrid PQC (next section); SSH and the Wazuh dashboard
are the remaining classical surfaces.

---

## Migration performed — hybrid PQC on the nginx front door

The inventory's highest-priority asymmetric surface is no longer just *planned* — it
is **done**. The Phase 5 nginx reverse proxy now terminates **HTTPS / TLS 1.3** and
negotiates a **hybrid post-quantum key exchange**:

- **HTTPS / TLS 1.3 on nginx**, with a self-signed certificate (a lab cert; a real
  deployment would use an ACME/CA-issued one).
- **`ssl_ecdh_curve X25519MLKEM768:X25519`.** The key-exchange group list leads with
  **X25519MLKEM768** — the hybrid that runs a classical **X25519** exchange concatenated
  with **ML-KEM-768** — and falls back to classical **X25519** for clients that don't
  support it, so the change is non-breaking.
- **Verified on the wire:** `openssl s_client -connect localhost:443 -groups X25519MLKEM768`
  reports **`Negotiated TLS1.3 group: X25519MLKEM768`** — confirming the handshake
  *actually used* the hybrid group, not merely that the server offered it.
- **Why it works here:** the box runs **OpenSSL 3.5.5**, which has **native ML-KEM
  support** — hybrid X25519MLKEM768 is built in, with no external provider
  (oqs-provider) required.

The result is exactly the hedge described earlier: the connection stays secure if
**either** half holds — classical X25519 covers the risk of a young ML-KEM
implementation, and ML-KEM-768 covers the quantum threat to X25519. The negotiated
secret still only ever keys a symmetric cipher (AES-256-GCM).

**Still classical (not yet migrated):** the **SSH access keys** (host + user, Phase 3)
and the **Wazuh dashboard TLS** (Phase 4) remain on classical asymmetric key exchange —
the next two surfaces on the list.

---

## Migration roadmap

1. **Inventory first (this phase).** Classify every key, certificate, and handshake
   by algorithm and by data-confidentiality lifetime. The table above is the
   starting artifact.
2. **Prioritise by confidentiality lifetime.** Long-lived secrets first, because of
   harvest-now-decrypt-later. **Key exchange before signatures** — confidentiality
   is the part exposed retroactively.
3. **Adopt hybrid PQC TLS.** Put **X25519MLKEM768** on the nginx front door
   (**done** — see *Migration performed*) and the Wazuh dashboard; enable a hybrid SSH
   KEX. Hybrid (not pure PQC) hedges against both an immature PQC implementation and the
   quantum break of the classical half.
4. **Plan signature migration.** Lower urgency (no retroactive forgery), but track
   ML-DSA support for long-lived trust anchors — CA roots, any code/firmware
   signing.
5. **Build for crypto-agility.** Structure TLS/SSH config so algorithms can be
   swapped without re-architecting. The durable lesson outlives any single
   algorithm: the next transition will be easier only if this one leaves seams to
   pull.

---

## Status

- [x] Runnable ML-KEM-768 + ML-DSA-65 demo via Open Quantum Safe, reproducible in a `python:3.12-slim` container ([`pqc/README.md`](../pqc/README.md)).
- [x] **ML-KEM-768** key exchange verified: public key 1,184 B, ciphertext 1,088 B, 32-byte shared secret matched on both sides.
- [x] **ML-DSA-65** signature verified: public key 1,952 B, signature 3,309 B, genuine message → `True`, tampered message → `False`. Documented the `verify()`-returns-bool footgun.
- [x] Measured PQC vs RSA-3072 sizes; documented the **3–8x** growth as the real migration cost (ML-DSA-65 signature ~8x).
- [x] Documented the threat model: **Shor** breaks all asymmetric (RSA/ECC), **Grover** only halves symmetric (AES-256 stays safe); **harvest-now-decrypt-later** makes confidentiality migration urgent today.
- [x] **Crypto inventory** of Acropolis: session `SECRET_KEY` (symmetric → quantum-safe, but a hardcoded classical flaw); nginx / SSH / Wazuh TLS (asymmetric → quantum-vulnerable → hybrid).
- [x] Migration roadmap recorded: inventory → prioritise long-lived secrets → hybrid PQC TLS → crypto-agility.
- [x] **Migration performed:** nginx front door moved to **hybrid X25519MLKEM768** (TLS 1.3, OpenSSL 3.5.5); verified on the wire — `openssl s_client … -groups X25519MLKEM768` reported `Negotiated TLS1.3 group: X25519MLKEM768`.
- [ ] **Future:** migrate the remaining classical surfaces — **SSH access keys** and the **Wazuh dashboard TLS** — to hybrid PQC.
