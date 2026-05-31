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
