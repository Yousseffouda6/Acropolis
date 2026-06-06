# Acropolis Notes

A small but complete, server-rendered **Markdown notes** web app — and the
Phase 1 **application-security target** for the [Acropolis lab](../README.md).
It looks and behaves like a real product, but it deliberately ships with a
catalogue of planted security flaws used throughout the lab's exploit → detect →
fix loop.

> ⚠️ **Intentionally vulnerable software.** This app is built to be attacked in a
> controlled environment. Do not deploy it to the public internet and do not put
> real data in it. Every flaw below is planted on purpose.

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

## The planted vulnerabilities

| # | Class | Where |
| - | ----- | ----- |
| 1 | Hardcoded secrets | `SECRET_KEY` / `ADMIN_API_KEY` in [`app.py`](app.py); surfaced on `/settings` |
| 2 | SQL injection | login query built by string concatenation in `/login` |
| 3 | IDOR | `/notes/<id>` fetches by id with no ownership check |
| 4 | Insecure deserialization | `/settings/import` calls `yaml.load(..., Loader=yaml.Loader)` |
| 5 | Vulnerable dependency | `requests==2.19.1` pinned in `requirements.txt` (never imported) |
| 6 | Stored XSS | note titles/bodies rendered as raw, unsanitised HTML |
| + | Bonus | `debug=True`, passwords stored in plaintext |

Full walkthrough — what / where / demo / detected-by / fix — lives in
[`../writeups/phase-1-appsec.md`](../writeups/phase-1-appsec.md).

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

`GEMINI_API_KEY` is read from a gitignored `.env` file; the Ollama backend needs no key.
All AI calls use the standard library, deliberately bypassing the pinned vulnerable `requests`.
Full writeup: [`../writeups/phase-6-ai-llm.md`](../writeups/phase-6-ai-llm.md).

## Verify the flaws still fire

```bash
python db.py
python test_exploits.py
```

`test_exploits.py` drives the Flask test client and asserts that all six
vulnerabilities are still exploitable. A passing run (`6/6`) is the regression
gate that proves a refactor didn't accidentally fix the lab.

## Layout

```text
app/
├── app.py              # Flask app + routes (all six vulns live here)
├── db.py               # schema + seed data
├── test_exploits.py    # exploit regression suite (6/6 must pass)
├── requirements.txt
├── Dockerfile
├── static/             # style.css, app.js, favicon.svg
└── templates/          # Jinja templates (base/shell + pages)
```
