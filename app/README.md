# Acropolis Notes

A small but complete, server-rendered **Markdown notes** web app — and the
Phase 1 **application-security target** for the [Acropolis lab](../README.md).
It looks and behaves like a real product, and it deliberately shipped with a
catalogue of planted security flaws used throughout the lab's exploit → detect →
fix loop — all **remediated in Phase 8**.

> ⚠️ **Security lab — read this.** This app was the lab's deliberately vulnerable
> target (Phases 1 & 6) and was **hardened in Phase 8**; the planted flaws below
> are fixed. The original vulnerable build is preserved at the git tag
> `v1.0-vulnerable` — check it out for demonstrations, but never deploy it to the
> public internet or put real data in it.

---

## Features

- **Accounts** — register, log in, log out.
- **Notes** — create, view, edit and delete notes.
- **Markdown** — note bodies are written in Markdown and rendered to HTML
  (headings, lists, tables, code blocks, blockquotes).
- **Tags** — tag notes and filter the library by tag from the sidebar.
- **Live search** — instant client-side filtering across titles, bodies and tags.
- **Dashboard** — note cards, per-account stats (note + tag counts) and a
  friendly empty state.
- **Import / export** — bring notes in from YAML or export them as a portable
  YAML file.
- **Settings** — profile page surfacing the account's API key.
- **Polished UI** — one cohesive, responsive stylesheet (no framework), classical
  "ink & patina on parchment" theme, accessible contrast, mobile + desktop.

## Tech stack

Server-rendered **Flask + Jinja2 + SQLite**. Markdown via `Markdown`, YAML via
`PyYAML`. Minimal vanilla JS for search, delete-confirm and toasts. No SPA, no
build step.

---

## Run locally

```bash
cd app
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python db.py        # create + seed acropolis.db
python app.py       # http://127.0.0.1:5000  (debug server, by design)
```

## Run with Docker

```bash
cd app
docker build -t acropolis-notes .
docker run --rm -p 5000:5000 acropolis-notes   # seeds the DB, then serves
```

## Seeded accounts

| Username | Password          | Notes                                   |
| -------- | ----------------- | --------------------------------------- |
| `alice`  | `password123`     | demo user with several notes            |
| `bob`    | `letmein`         | demo user                               |
| `admin`  | `acropolis-admin` | owns the note holding the IDOR **flag** |

The admin's note (id **6** on a fresh seed) contains
`FLAG{idor_let_me_read_the_admin_note}`.

---

## The planted vulnerabilities — and their Phase 8 fixes

All of these were planted on purpose and **fixed in Phase 8**. The
deliberately-vulnerable build is preserved at the git tag `v1.0-vulnerable`.

| # | Class | Where (vulnerable build) | Fix (Phase 8) |
| - | ----- | ----- | ----- |
| 1 | Hardcoded secrets | `SECRET_KEY` / `ADMIN_API_KEY` in `app.py`; surfaced on `/settings` | read from env; random `SECRET_KEY` fallback |
| 2 | SQL injection | login query built by string concatenation in `/login` | parameterised query + hashed-password check |
| 3 | IDOR | `/notes/<id>` fetched by id with no ownership check | ownership enforced; non-owner → 404 |
| 4 | Insecure deserialization | `/settings/import` called `yaml.load(..., Loader=yaml.Loader)` | `yaml.safe_load` |
| 5 | Vulnerable dependency | `requests==2.19.1` pinned (never imported) | removed (was unused) |
| 6 | Stored XSS | note titles/bodies rendered as raw HTML | `nh3` sanitises rendered HTML; title auto-escaped |
| + | Bonus | `debug=True`, plaintext passwords | `debug` off by default; salted `werkzeug` hashes |

Full walkthrough of the flaws is in
[`../writeups/phase-1-appsec.md`](../writeups/phase-1-appsec.md); the remediation
is in [`../writeups/phase-8-remediation.md`](../writeups/phase-8-remediation.md).

### Phase 6 — AI/LLM flaws (`/ai` assistant)

The **AI Assistant** (`/ai`) adds five more planted flaws, mapped to the OWASP Top 10 for LLM
Applications. Two backends are supported: **Gemini 2.5 Flash Lite** (cloud) and
**TinyLlama 1.1B** (local via Ollama — no internet, no safety training). These flaws are
separate from the six above and from the `6/6` Phase-1 regression gate:

| # | Class | OWASP | Where |
| --- | ----- | ----- | ----- |
| AI-1 | Prompt injection | LLM01 | only a natural-language guard in `SYSTEM_PROMPT`; alignment-dependent — confirmed on TinyLlama |
| AI-2 | System-prompt secret leak | LLM06 | admin flag hardcoded in `SYSTEM_PROMPT` in [`app.py`](app.py) |
| AI-3 | Insecure output handling → XSS | LLM02 | `{{ reply\|safe }}` in `templates/ai.html` — model-driven XSS, confirmed both models |
| AI-4 | Indirect prompt injection | LLM01 | notes injected verbatim via `notes_for_assistant()` — untrusted data treated as instructions |
| AI-5 | Excessive Agency | LLM08 | `delete_note` callable with no confirmation; chained with AI-4 to delete notes silently |

All five were **fixed in Phase 8**: the secret was removed from `SYSTEM_PROMPT`, the model's
create/update/delete tools were removed (read-only assistant), the reply is sanitised, and note
content is framed as untrusted data with an output guard (prompt injection is *mitigated*, not
eliminated).

`GEMINI_API_KEY` is read from a gitignored `.env` file; the Ollama backend needs no key.
All AI calls use the standard library (the unused `requests` pin was removed in Phase 8).
Writeup: [`../writeups/phase-6-ai-llm.md`](../writeups/phase-6-ai-llm.md) · remediation:
[`../writeups/phase-8-remediation.md`](../writeups/phase-8-remediation.md).

### Phase 7 — Post-quantum crypto inventory

The lab's [post-quantum cryptography module](../pqc/) (Phase 7) demos the NIST PQC standards
**ML-KEM-768** (FIPS 203, key exchange) and **ML-DSA-65** (FIPS 204, signatures), then inventories
every use of crypto across the lab. The only one inside this app is **session-cookie signing**:
Flask signs the session with `SECRET_KEY` via `itsdangerous` (HMAC-SHA). That is **symmetric**
crypto, so it is **quantum-safe** — a quantum computer's Grover speedup only halves symmetric
strength, leaving HMAC effectively intact. Its only problem was *classical*: the key used to be
hardcoded (old VULN #1) — **fixed in Phase 8**, now read from the environment. The asymmetric
crypto lives in the deployment layer: the **nginx front door is migrated** to hybrid PQC
(`X25519MLKEM768`), while SSH and the Wazuh dashboard TLS remain classical (future work).
Full inventory: [`../writeups/phase-7-pqc.md`](../writeups/phase-7-pqc.md).

## Verify the fixes hold

```bash
python db.py
python test_exploits.py
```

`test_exploits.py` drives the Flask test client and asserts that all six planted
exploits are now **blocked**. A passing run (`6/6`) is the remediation regression
gate — it fails if a vulnerability is reintroduced. (In the `v1.0-vulnerable`
build the same suite passed by proving the exploits *fired*.)

## Layout

```text
app/
├── app.py              # Flask app + routes (hardened in Phase 8)
├── db.py               # schema + seed (salted password hashes)
├── test_exploits.py    # remediation regression gate (6/6 = all exploits blocked)
├── list_models.py      # helper: list Gemini models available to your API key
├── requirements.txt
├── Dockerfile
├── static/             # style.css, app.js, favicon.svg
└── templates/          # Jinja templates (base/shell + pages)
```
