# Phase 2 — DevSecOps: the security pipeline

Phase 1 built a deliberately vulnerable artifact ([Acropolis Notes](./phase-1-appsec.md)).
Phase 2 wraps it in a **CI/CD security pipeline** that scans every commit and pull
request, then surfaces what it finds. The interesting result is not that the
scanners light up — it is *which* planted flaw they each catch, which they miss,
and the one flaw that **no automated tool catches at all**.

The workflow lives in [`.github/workflows/security.yml`](../.github/workflows/security.yml).

---

## Design decision: report, don't block (yet)

Acropolis Notes is vulnerable **on purpose**, and the flaws must stay exploitable
so Phases 4–5 can detect and attack the same artifact. A normal pipeline would
fail the build on a HIGH finding — but that would pressure us to "fix" the lab.

So every job runs with `continue-on-error: true` and the scan steps swallow
non-zero exits (`|| true`). **The pipeline stays green while the findings still
surface** — as SARIF in the GitHub *Security* tab and as a downloadable report
artifact. We get the visibility of a security gate without the gate fighting the
lab's purpose.

This is a temporary, deliberate posture. The progression is the lesson:

> **report (Phase 2) → triage → gate (Phase 8).** Once Phase 8 fixes the planted
> flaws, the guards flip to **blocking**: drop `continue-on-error` / `|| true`, add
> failing severity thresholds, and any *re-introduced* vulnerability breaks CI.

---

## The pipeline at a glance

| Job | Tool | Class | Scans | Output lands in |
| --- | ---- | ----- | ----- | --------------- |
| `sast` | Semgrep (`--config=auto`) | SAST — static code analysis | `app/` source | Security tab (SARIF, category `semgrep`) |
| `secrets` | gitleaks | Secret scanning | full git **history** (`fetch-depth: 0`) | Job log / gitleaks output |
| `sca` | Trivy | SCA — deps + image | `requirements.txt`, then the built image | Security tab (SARIF, `trivy-deps`) + job log (image table) |
| `dast` | OWASP ZAP baseline | DAST — running app | live container on `:5000` | Actions **artifact** `zap-report.html` |

Triggers: `push`, `pull_request`, `workflow_dispatch`. Permissions:
`contents: read`, `security-events: write` (the latter is what lets the jobs
upload SARIF to the Security tab).

A networking note on the DAST job: ZAP runs in its **own** container, so it is
started with `--network host` to reach the app on `localhost:5000`. The job also
waits in a readiness loop (`curl -sf .../login`) before scanning, so ZAP never
races the container's startup + DB seed.

---

## The catch / miss matrix

This is the heart of Phase 2. Each planted flaw is mapped against each scanner
*class*. ✓ = reliably caught, ✗ = missed, △ = partial / tool-dependent.

| # | Planted flaw | SAST | Secrets | SCA | DAST (baseline) | Net result |
| - | ------------ | :--: | :-----: | :-: | :-------------: | ---------- |
| 1 | Hardcoded secrets | ✓ | ✓ | – | – | **caught** (twice) |
| 2 | SQL injection (login) | ✓ | – | – | ✗ | **caught** (static only) |
| 3 | **IDOR** (`GET /notes/<id>`) | ✗ | – | – | ✗ | **MISSED by everything** |
| 4 | Insecure YAML deserialization | ✓ | – | – | ✗ | **caught** (static only) |
| 5 | Vulnerable dependency | – | – | ✓ | – | **caught** |
| 6 | Stored XSS | △ | – | – | ✗ | caught **only** by Semgrep's `|safe` rule |
| + | `debug=True` | ✓ | – | – | ✗ | **caught** (static) |
| + | Bind to `0.0.0.0` | ✓ | – | – | – | **caught** (static) |
| + | Plaintext passwords | △ | – | – | – | weak — really a manual-review find |
| – | Missing security headers | – | – | – | ✓ | the baseline DAST's main positive |

How to read the columns:

- **SAST (Semgrep / Bandit)** catches *dangerous code patterns*: the string-built
  SQL query, `yaml.load(..., Loader=yaml.Loader)`, the hardcoded `SECRET_KEY`,
  `debug=True`, and the bind-to-all-interfaces. Stored XSS is **tool-dependent**:
  Semgrep's autoescape-off / `|safe`-on-user-data rules can flag it, but Bandit
  does not — so it sits at △, not a guaranteed catch.
- **Secret scanning (gitleaks)** catches the committed `SECRET_KEY` and API key —
  and because it scans the **full history** (`fetch-depth: 0`), it still finds a
  secret even after a later commit "removes" it. Rotation, not deletion, is the
  only real fix.
- **SCA (Trivy / pip-audit)** catches the pinned `requests==2.19.1` and its
  outdated transitive deps (`urllib3`, `idna`) — all with published CVEs — plus
  base-image CVEs from the image scan.
- **DAST (ZAP baseline)** is **passive and unauthenticated**: it never logs in and
  never actively injects payloads. So it walks the public surface, flags missing
  security headers, and **misses every flaw that lives behind the login**.

---

## Headline lesson: IDOR is caught by nothing

The IDOR in `GET /notes/<id>` is **invisible to every automated scanner in the
pipeline**, and that is the single most important takeaway of Phase 2.

The reason is structural: IDOR is **missing business logic**, not a dangerous code
pattern. The query is perfectly safe-looking —

```python
note = query_db("SELECT * FROM notes WHERE id = ?", (note_id,), one=True)
```

— it is parameterized, there is no injection, no eval, no unsafe API. SAST sees
nothing wrong because *nothing is syntactically wrong*. What is missing is the
clause that was never written: `AND user_id = ?`. A tool cannot flag the absence
of an authorization check it has no way to know should exist.

DAST cannot see it either: the baseline scan never authenticates, so it never even
reaches `/notes/<id>` as a logged-in user, let alone compares one user's view of
an object against another's.

This is exactly why **OWASP ranks Broken Access Control as the #1 web application
risk** (A01:2021). Access-control bugs are common, high-impact, and *resistant to
automation* — they need authenticated, context-aware testing (an authenticated
active DAST scan, or manual testing in Burp/ZAP comparing responses across
sessions) and code review that understands intent. Phase 5 catches this IDOR with
exactly that kind of testing, and Phase 4/5 writes a detection rule for the
runtime signature (one session reading many sequential object ids).

---

## Second lesson: the baseline DAST's blind spot is itself the point

The ZAP **baseline** scan is passive and unauthenticated by design — it is meant
to be a fast, safe, every-commit check. The consequence is that it **misses the
SQLi, IDOR, stored XSS, and YAML deserialization**, because all four live behind
the login form. What it *does* reliably report is the set of **missing security
headers** (CSP, X-Content-Type-Options, etc.) on the public pages.

That gap is a teaching point, not a failure:

- The dynamically-confirmable bugs (SQLi, XSS) *are* still caught by the pipeline —
  but **statically**, by SAST. Static and dynamic analysis cover different ground;
  neither alone is sufficient.
- To find SQLi/XSS/IDOR **dynamically**, you need an **authenticated, active** scan
  — ZAP with a session/auth context and the active scanner enabled, or `sqlmap`
  with a valid cookie. That is a deliberate Phase 5 escalation, not something you
  want running unattended on every commit (active scans are intrusive).

---

## Locally verified

GitHub Actions cannot be executed from here, so two of the scanner *classes* were
run locally against the app to confirm they catch the planted flaws. Exact
commands:

```bash
# YAML validity of the workflow
python -c "import yaml; yaml.safe_load(open('.github/workflows/security.yml'))"

# SAST surrogate (Bandit) — same class as Semgrep
pip install bandit && bandit -r app          # (local run excluded app/.venv)

# SCA against the pinned manifest
pip install pip-audit && pip-audit -r app/requirements.txt
```

**Bandit** reported the planted code-pattern flaws — `B105` hardcoded secret
(VULN #1), `B608` string-built SQL (VULN #2), `B506` unsafe `yaml.load` (VULN #4),
`B201` `debug=True`, and `B104` bind-to-all-interfaces — confirming the SAST
column. (It did **not** flag the IDOR or the stored XSS, exactly as the matrix
predicts.)

**pip-audit** reported **requests 2.19.1** with five advisories, headlined by
`PYSEC-2018-28` (**CVE-2018-18074** — `Authorization` header leaked across a
cross-host redirect; fixed in 2.20.0), plus its outdated transitive deps
`urllib3 1.23` and `idna 2.7`, confirming the SCA column. (Trivy in CI reports the
same dependency CVEs and adds base-image CVEs.)

---

## How to view the results

- **SARIF findings (SAST + SCA):** open the repo's **Security** tab →
  *Code scanning alerts*. Findings are grouped by the `category` each job uploads
  (`semgrep`, `trivy-deps`), so you can tell which scanner raised what.
- **The ZAP report (DAST):** open the workflow run under the **Actions** tab and
  download the **`zap-report.html`** artifact; open it in a browser for the full
  passive-scan findings (mostly the missing-headers list).
- **Secret findings:** in the `secrets` job log (gitleaks prints the file, commit,
  and rule for each hit).

---

## Status

- [x] `security` workflow created — four jobs (SAST, secrets, SCA, DAST).
- [x] Triggers `push` / `pull_request` / `workflow_dispatch`; `security-events: write`.
- [x] Report-not-block posture (`continue-on-error` + `|| true`) so the lab stays intact.
- [x] SARIF uploads to the Security tab (Semgrep + Trivy); ZAP report as an artifact.
- [x] Workflow YAML validated; Bandit + pip-audit run locally and confirm the catches.
- [x] Catch/miss matrix documented; IDOR confirmed uncaught by automation.
- [ ] **Phase 8:** flip the guards to blocking once the planted flaws are fixed.
