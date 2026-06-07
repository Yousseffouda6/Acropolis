# Phase 8 — Remediation & publication: close the loop

This is the phase the whole lab was built to reach. Phases 1 and 6 planted
thirteen vulnerabilities; Phases 2–5 scanned, deployed, attacked and detected
them; Phase 8 **fixes every one of them** and turns the safety nets around. The
standing rule that kept the flaws alive ("never fix them, keep the exploit suite
at 6/6") is lifted here — that rule existed precisely so this phase would have
something to remediate.

Three things change at once, and they are the point of the exercise:

1. Every planted flaw is fixed while the app stays fully functional.
2. The exploit suite is **inverted** — `test_exploits.py` now passes when the
   exploits are *blocked*, so it guards against regressions instead of proving
   the lab.
3. The DevSecOps pipeline flips from **report-only to blocking** — a reintroduced
   flaw now breaks the build.

> **The vulnerable build is preserved.** The intentionally-vulnerable version
> (Phases 0–7) is tagged **`v1.0-vulnerable`**. Check it out
> (`git checkout v1.0-vulnerable`) any time to demonstrate the original exploits;
> `main` is now the hardened build.

---

## At a glance

| | |
| --- | --- |
| Fixed | **13** planted flaws — 6 app + 5 AI/LLM + 2 bonus |
| Regression gate | `app/test_exploits.py` inverted → **6/6 = exploits blocked** |
| Pipeline | DevSecOps gate flipped to **blocking** (Semgrep `--error`, Trivy `exit-code 1`, gitleaks + allowlist, ZAP, and a `test_exploits.py` hard gate) |
| Preserved | vulnerable build at tag `v1.0-vulnerable` |
| Honest caveat | prompt injection is **mitigated, not eliminated** |

---

## The six application fixes

Each fix keeps the feature working — the flaw closes, the product does not change
for legitimate users.

### #1 — Hardcoded secrets → environment-sourced

*CWE-798 (Use of Hard-coded Credentials) · OWASP A05:2021 Security Misconfiguration*

**Before.** The Flask session key and an API key were string literals in source,
and the API key was shown to any logged-in user on `/settings`. A leaked
`SECRET_KEY` lets an attacker forge session cookies offline.

```python
SECRET_KEY = "acropolis-dev-secret-key-2026-do-not-rotate"
ADMIN_API_KEY = "acro_live_sk_8f3b1c9d2e5a4f6b7c8d9e0f1a2b3c4d"
```

**After.** Both are read from the environment; if `SECRET_KEY` is unset the app
generates a strong random key at startup. No secret lives in source.

```python
SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY", "")
```

An [`app/.env.example`](../app/.env.example) documents every variable; real
secrets stay in the gitignored `.env` / a secret manager.

### #2 — SQL injection → parameterised query

*CWE-89 (SQL Injection) · OWASP A03:2021 Injection*

**Before.** The login query concatenated untrusted input, so
`' OR '1'='1' --` logged in as the first user with no password.

```python
query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
```

**After.** A parameterised lookup by username, then a constant-time hash check.
Input never reaches SQL string construction.

```python
row = query_db("SELECT * FROM users WHERE username = ?", (username,), one=True)
if row and check_password_hash(row["password"], password):
    ...
```

### #3 — IDOR → enforced ownership

*CWE-639 (Authorization Bypass Through User-Controlled Key) · OWASP A01:2021 Broken Access Control*

**Before.** `/notes/<id>` fetched a note by id with no ownership check, so any
user could read the admin's flag note by guessing the id. (This is the flaw no
scanner caught in Phase 2 — broken access control is missing logic, not a
dangerous pattern.)

**After.** The note must belong to the signed-in user; a non-owner — or a missing
id — gets a `404` (the route refuses to confirm the note even exists).

```python
note = query_db("SELECT * FROM notes WHERE id = ?", (note_id,), one=True)
if note is None or note["user_id"] != session["user_id"]:
    abort(404)
```

### #4 — Insecure deserialization → `safe_load`

*CWE-502 (Deserialization of Untrusted Data) · OWASP A08:2021 Software and Data Integrity Failures*

**Before.** YAML import used the full loader, so a tag like
`!!python/object/apply:os.system ["id"]` ran arbitrary commands during parsing.

**After.** `yaml.safe_load` builds only plain scalars/lists/dicts and refuses the
`!!python/object` tags — the import feature still works for ordinary note YAML.

```python
data = yaml.safe_load(raw)
```

### #5 — Vulnerable dependency → removed

*CWE-1104 (Use of Unmaintained Third Party Components) · OWASP A06:2021 Vulnerable and Outdated Components*

**Before.** `requests==2.19.1` (a knowingly outdated pin) sat in
`requirements.txt`, never imported, purely as SCA bait.

**After.** It is removed entirely. The AI calls were always built on the stdlib
`urllib`, so the app now ships **no known-vulnerable dependency** — Trivy's SCA
job comes back clean.

### #6 — Stored XSS → sanitised output

*CWE-79 (Cross-site Scripting) · OWASP A03:2021 Injection*

**Before.** Note titles and Markdown bodies rendered as raw HTML via `|safe`, so a
note body of `<script>…</script>` executed when viewed.

**After.** `render_markdown()` runs the rendered HTML through **`nh3`** (a
maintained Rust/ammonia sanitiser) before it is marked safe; the title is
auto-escaped. Markdown formatting (headings, lists, tables, code) survives;
`<script>`, inline event handlers and `javascript:` URLs are stripped.

```python
html = markdown.markdown(text or "", extensions=["fenced_code", "tables", "nl2br"])
return nh3.clean(html)
```

This one chokepoint also sanitises the AI assistant's reply (see AI-3).

---

## The two bonus fixes

**Debug mode** *(CWE-489 Active Debug Code · OWASP A05:2021).* `debug=True`
exposed the interactive Werkzeug debugger — an RCE console. It now defaults
**off**; local debugging is opt-in via `FLASK_DEBUG=1`.

```python
debug = os.environ.get("FLASK_DEBUG", "").lower() in ("1", "true", "yes")
app.run(host="0.0.0.0", port=5000, debug=debug)
```

**Plaintext passwords** *(CWE-256 Plaintext Storage of a Password · OWASP A02:2021
Cryptographic Failures).* Passwords were stored verbatim. Both the seed (`db.py`)
and registration now store a salted `werkzeug` hash, and login verifies with
`check_password_hash`. Users log in with the same passwords as before.

---

## The five AI/LLM fixes

The `/ai` assistant's flaws map to the OWASP Top 10 for LLM Applications.

### AI-2 — Secret in the system prompt → removed

*OWASP LLM06 Sensitive Information Disclosure · CWE-200*

The flag was embedded in `SYSTEM_PROMPT` behind a polite "never reveal"
instruction — which any jailbreak walked past. **The real fix is to remove the
secret entirely:** secrets never belong in a prompt. You cannot leak what is not
there. The system prompt now contains only behavioural rules, no data.

### AI-5 — Excessive Agency → read-only assistant

*OWASP LLM08 Excessive Agency*

The model was handed `create_note` / `update_note` / `delete_note` tools that
executed immediately, with no confirmation — so natural language (or injected
note content) could silently mutate the user's data. **The tools and the
`run_note_action` executor were removed entirely.** The assistant can summarise
and answer questions about notes; it can no longer change them. An LLM should not
hold unconfirmed write access to user data.

### AI-3 — Insecure output handling → sanitised

*OWASP LLM02 Insecure Output Handling · CWE-79*

The model's reply was rendered with `|safe`, so a model-produced `<script>`
executed in the browser (model-driven XSS). The reply now flows through the same
`render_markdown()`/`nh3` chokepoint as note bodies — Markdown still renders,
scripts are stripped.

### AI-1 & AI-4 — Prompt injection (direct + indirect) → mitigated

*OWASP LLM01 Prompt Injection · CWE-1427 (Improper Neutralization of Input Used for LLM Prompting)*

Note content is attacker-controllable free text that flowed into the model verbatim
(indirect injection), and a crafted user message could override the weak prompt
guard (direct injection). Phase 8 applies **defense in depth**:

- **Delimited, declared-untrusted data.** Note content is wrapped in explicit
  `=== BEGIN/END MY NOTES ===` markers, and the system prompt instructs the model
  to treat everything between them as *data* and never to obey instructions found
  inside it.
- **Output guard.** Every reply passes through `guard_model_output()`, which
  redacts flag-shaped tokens (`FLAG{…}`) — so even if some future prompt did carry
  a secret, it could not surface through this UI.

> **Stated honestly: this mitigates prompt injection, it does not eliminate it.**
> There is no complete, deterministic fix for prompt injection against a
> probabilistic model — delimiting and instructions raise the bar but a
> sufficiently clever prompt can still confuse the model. The durable lessons are
> the ones that *are* deterministic: keep secrets out of the prompt (AI-2), don't
> give the model unconfirmed authority (AI-5), and sanitise its output (AI-3). The
> remaining injection risk is bounded because those three are no longer
> exploitable into anything that matters.

---

## The pipeline is now a blocking gate

Through Phases 2–7 the DevSecOps workflow ran **report-only** (`continue-on-error`
everywhere) because the flaws had to survive for the attack/detect phases. With
them fixed, [`security.yml`](../.github/workflows/security.yml) is a **blocking
gate**:

- **Semgrep** runs with `--error`; **Trivy** (deps + image) with `exit-code: 1`
  and `ignore-unfixed` — findings fail the build.
- **gitleaks** blocks on any *new* secret. The intentional lab secrets removed in
  Phase 8 are allow-listed in [`.gitleaks.toml`](../.gitleaks.toml) so the
  full-history scan stays green on past commits.
- A new **`regression`** job runs `app/test_exploits.py` as a hard gate — the
  inverted suite that asserts all six exploits stay blocked.
- ZAP keeps `-I` so purely passive header warnings (future hardening, not a
  planted flaw) are reported, not blocking; a scan error still fails CI.

The report → gate progression was always the goal: the same scanners that merely
*observed* the flaws now *prevent their return*.

---

## Security posture: before vs after

| Area | `v1.0-vulnerable` | `main` (Phase 8) |
| --- | --- | --- |
| Secrets | hardcoded in source, shown on `/settings` | environment-sourced; none in source |
| Auth | SQLi bypass; plaintext passwords | parameterised query; salted hashes |
| Access control | IDOR — any note readable by id | ownership enforced (404 for non-owners) |
| Deserialization | `yaml.load` → RCE | `yaml.safe_load` |
| Dependencies | `requests==2.19.1` (vulnerable) | removed; no known-vulnerable dep |
| Output | raw HTML → stored XSS | `nh3`-sanitised |
| Debugger | `debug=True` (RCE console) | off by default |
| AI: prompt secret | flag baked into system prompt | removed |
| AI: agency | unconfirmed create/update/delete | read-only |
| AI: output | unescaped (model-driven XSS) | sanitised |
| AI: injection | trivially exploitable | mitigated (defense in depth) |
| Exploit suite | 6/6 **exploitable** | 6/6 **blocked** (regression gate) |
| CI pipeline | report-only | **blocking** |

The five-phase build/attack/detect loop now has its final segment: **remediate**.
Fixing the application code closes the exploit paths, turns the CI gate green on
the right things and red on regressions, and (for the one classical-but-real
crypto flaw) ties back to the Phase 7 inventory. The same artifact, seen one last
way.

---

## Status

- [x] All **6 application flaws** fixed (secrets, SQLi, IDOR, YAML RCE, vulnerable dep, stored XSS) with features intact.
- [x] Both **bonus flaws** fixed (`debug` off by default; salted password hashes).
- [x] All **5 AI/LLM flaws** fixed; prompt injection documented as **mitigated, not eliminated**.
- [x] `app/test_exploits.py` **inverted** into a remediation regression gate — **6/6 exploits blocked**.
- [x] DevSecOps pipeline flipped to **blocking**; gitleaks allowlist for the removed historical lab secrets; `test_exploits.py` added as a CI hard gate.
- [x] Vulnerable build preserved at the tag **`v1.0-vulnerable`**.
- [x] Audit discrepancies resolved (nginx hybrid-PQC config committed; docs synced; planned dirs reconciled).
- [ ] **Future hardening (not planted flaws):** CSP / security headers on the app itself, PQC migration of SSH + the Wazuh dashboard TLS, and a CSRF token on state-changing forms.
