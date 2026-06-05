# Phase 5 — Attack & Detect: the loudest attack was the harmless one

This is where the lab's whole premise — *build it, secure it, attack it, detect
it* — closes into a loop. From a **Kali** VM we attack the live Acropolis host
([Phase 3](./phase-3-cloud.md)); from the **Wazuh** SIEM ([Phase 4](./phase-4-blueteam.md))
we watch what shows up. Three attack vectors, then the finding that reframes the
whole phase: **detection turned out to be inversely correlated with danger.** The
noisy, useless scan generated roughly **7,000 alerts**; a full account takeover
generated **zero**.

> **Scope.** Every attack here is run against the author's own lab, over the
> controlled channel established in Phase 3. Real IPs, keys, and account IDs are
> redacted to placeholders (`<SERVER_IP>`, `<KEY>.pem`, `<weak-user>`).

---

## The engagement at a glance

| | |
| --- | --- |
| Attacker | Kali Linux VM on the operator's Mac, NAT'd behind the operator's home IP |
| Target | the Phase 3 Acropolis host (`t3.micro`, `eu-central-1`) |
| Observer | the Phase 4 Wazuh SIEM — agent on the target, manager on a separate box |
| Vectors | (1) SSH brute force · (2) post-compromise host actions · (3) web-layer attacks |
| Headline | a noisy scan = **~7,000 alerts**; a successful SQLi login bypass = **0 alerts** |

---

## Setup: a fair fight on a controlled channel

Phase 3 deliberately closed everything but SSH/22 (scoped to the operator's IP).
Two of the three vectors need network reach the lockdown denies, so the engagement
opens **narrow, temporary, attacker-only** exposure — never the public internet:

- The Kali VM runs on the operator's Mac and shares its public IP via **NAT**, so
  its traffic arrives from the **same `/32`** the security group already allows.
  The attack therefore comes from an authorized source — which is exactly what
  keeps it in-scope and bounded to systems the author owns.
- For the web vector, port 80 is opened **only to that attacker IP** (below), not
  to `0.0.0.0/0`. The Phase 3 rule — *never expose the vulnerable app to the open
  internet* — still holds.

The point of the phase is not "can a weak box be hacked" (it can, by design). It
is **which attacks the blue-team instrumentation sees, and which it doesn't.**

---

## Vector 1 — SSH brute force (T1110 → T1078)

**The attack.** `hydra` from Kali, throwing a wordlist at SSH password auth:

```bash
hydra -l <weak-user> -P /usr/share/wordlists/rockyou.txt ssh://<SERVER_IP>
```

A **temporary** weak account (`<weak-user>`) was created on the box for this test
so a password could realistically be "found" — the real operator account is
key-only and was never exposed. The account was deleted afterward.

**Two honest wrinkles** (the kind of detail that doesn't make it into tutorials):

- **NAT.** Because Kali is NAT'd behind the Mac, hydra's packets reach the box
  from the operator's home IP — the one address the security group permits. The
  brute force comes from an *allowed* source, which is what makes the test legal
  and contained.
- **Ubuntu 26.04 sshd.** Modern OpenSSH defaults can leave keyboard-interactive
  auth off, so hydra's `ssh` module had nothing to drive. Enabling
  `KbdInteractiveAuthentication yes` gave the brute force a password method to
  hammer (a deliberate, temporary loosening for the exercise).

**What Wazuh saw.** A burst of sshd authentication-failure events, which the
manager correlates into:

- rule **5712** — *"SSHD brute force trying to get access to the system"* (level
  10), the correlation rule that fires once failures cluster past a threshold;
- then rule **5715** — *sshd authentication success* — once hydra found the weak
  password.

That pair is the textbook signature: not just "someone is guessing," but **the
moment the guessing won** — the **T1110 → T1078** pivot (Brute Force → Valid
Accounts) laid out in the timeline.

---

## Vector 2 — Post-compromise on the host (T1136, privilege escalation, tampering)

Assume the attacker is now *on* the box (via vector 1, or the app's YAML RCE).
What do they do next, and does the host notice? This vector doubles as a **real,
permanent detection improvement**.

**Hardening first (kept).** Before simulating anything, real-time **File Integrity
Monitoring** was enabled on `/root` and `/etc` with `realtime="yes"` and
`report_changes="yes"`. The first reports the change the instant it happens; the
second includes a **diff of what changed**, not merely *that* something did.

**The simulated actions, and what fired:**

- **Create a new user** → rule **5902** (new account added), MITRE **T1136**
  (Create Account) — a classic persistence move, caught.
- **Escalate to root via `sudo`** → rule **5402** (*successful sudo to ROOT*),
  MITRE **T1548.003** — the privilege change is logged and alerted.
- **Edit a file under `/etc`** → rule **550** (*Integrity checksum changed*), and
  because `report_changes` was on, the alert carried **the exact line the attacker
  added** — the malicious content itself, not just a filename.

**Cleanup / what stayed.** The test user and the file edits were reverted; the
**FIM configuration was kept** as a permanent improvement. Real-time FIM with
`report_changes` is precisely the blind-spot fix Phase 4 promised Phase 5 would
produce.

---

## Vector 3 — Web-layer attacks (the loud ones)

To attack the *web app* over the network — not just through the SSH tunnel — an
**nginx reverse proxy** was placed in front of the loopback-bound container, and
its access logs were fed into Wazuh as a new log source. Port **80** was opened to
the **attacker's IP only**, giving the web layer a network presence to attack and
to monitor while still honoring the Phase 3 rule.

**The attacks.** From Kali: a `nikto` scan, plus hand-thrown **GET-based** SQLi,
XSS, and path-traversal probes against the proxied app.

**What Wazuh saw — loudly.** nginx's access logs lit up the web rule set:

- rule **31101** — web 4xx/5xx errors, in the **thousands** (nikto hammering
  paths that don't exist);
- rule **31103** — SQL-injection pattern in a URL;
- rule **31105** — XSS pattern in a URL;
- rule **31106** — *"web attack returned code 200"* (apparent success).

All told, on the order of **~7,000 alerts**. By the dashboard's count this looks
like a triumph: the SIEM *screamed*.

It was screaming at the wrong thing.

---

## The key finding: the dangerous attack was silent

Here is the inversion that defines Phase 5.

The **real** attack on this app is not a GET-based probe — it is the planted SQL
injection **login bypass** (VULN #2), delivered as a **POST** to `/login`:

```text
username=' OR '1'='1' --
password=anything
```

Run against the proxied app, this **succeeded**: a **302 redirect** to
`/dashboard`, a valid signed session cookie, logged in as a real user — a full
**authentication bypass / account takeover**.

Wazuh raised **zero alerts.**

**Why nothing fired:**

- nginx access logs record the **request line** — method, URL path, status code —
  but **never the request body**. The injection payload lives in the POST body, so
  it never appears in the data Wazuh is reading.
- The *result* looks utterly normal on the wire: `POST /login → 302`, then an
  authenticated `GET /dashboard → 200`. A successful redirect to a legitimate
  endpoint matches **no** web-attack signature. There is nothing anomalous to key
  on.

So the lab delivered its sharpest lesson as a contrast:

> A useless, noisy vulnerability scan generated **~7,000 alerts**. A successful,
> full **account takeover** generated **0**. Detection was **inversely correlated
> with danger** — the louder the attack, the less it mattered; the quieter it was,
> the worse it was.

This is not a Wazuh failure; it is a **visibility** failure. Detection is only ever
as good as its data source, and a URL-only access log is blind to body-borne
attacks *by construction*.

**The chain gets worse.** The session minted by that bypass is signed with the
app's **hardcoded `SECRET_KEY`** (VULN #1). With the key known, an attacker doesn't
even need the SQLi: they can **forge a valid session cookie for any user —
including `admin` — entirely offline** (MITRE **T1606.001**, Forge Web
Credentials). No login request, nothing for the proxy or the SIEM to log at all.
The quiet attack can be made *completely invisible*.

**Fixing the blind spot.** Catching the POST SQLi needs a sensor that can see the
body or the resulting query:

- **Application-level logging** — have the app log authentication attempts (and
  the offending input) so the SIEM gets a body-aware signal at the source.
- **A body-inspecting WAF** — e.g. ModSecurity in front of nginx with an SQLi rule
  set, matching the payload before it reaches the app.
- **Database query monitoring** — watch for the tautological/malformed query
  (`OR '1'='1'`) at the DB layer, where the injection actually lands.

Each moves the sensor to where the evidence is. That is the real takeaway:
**put the sensor where the attack lives, not where it's loudest.**

---

## Caught vs. missed

| Attack | Layer | Wazuh rule(s) | MITRE | Detected? |
| ------ | ----- | ------------- | ----- | --------- |
| SSH brute force | network / SSH | **5712** (level 10) | T1110 | ✓ loud |
| Brute-force **success** (valid login) | network / SSH | **5715** | T1110 → **T1078** | ✓ |
| New user created | host | **5902** | T1136 | ✓ |
| Sudo to root | host | **5402** | T1548.003 | ✓ |
| File tampering in `/etc`, `/root` | host (FIM) | **550** + `report_changes` diff | T1565 (intent-agnostic) | ✓ **with content** |
| nikto vulnerability scan | web | **31101** (thousands) | T1595.002 | ✓ very loud |
| GET-based SQLi / XSS / traversal | web | **31103 / 31105 / 31106** | T1190 | ✓ loud |
| **POST SQLi login bypass** (`' OR '1'='1' --`) | web | **— none —** | T1190 → **T1078** | ✗ **silent** |
| Forged session via hardcoded `SECRET_KEY` | offline | **— none —** | **T1606.001** | ✗ **invisible** |

The pattern is unmistakable: every **noisy** attack was caught; the two attacks
that actually **take over the account** were caught by **nothing**.

---

## How this sets up Phase 8 (remediation)

Phase 5 hands Phase 8 both a punch list *and* a way to prove the fixes work — the
caught/missed table is, read the other way, a **test plan**:

- **Fix the app.** Parameterize the login query (kills the SQLi), move `SECRET_KEY`
  out of source and rotate it (kills the offline session forgery), scope note
  lookups to their owner (kills the IDOR that no scanner ever caught), `safe_load`
  the YAML, drop `|safe` / autoescape, upgrade `requests`.
- **Verify two ways.** After the fix, the Phase 2 pipeline should go green *on
  merit* (not via `continue-on-error`), and the attacks that **succeeded** here
  should now **fail**: the `' OR '1'='1' --` login returns an auth error instead of
  a 302, and `app/test_exploits.py` flips from **6/6 exploitable** to **0/6**.
- **Keep the detection wins.** The real-time FIM config stays; the blind-spot
  remediation (app-level auth logging / a body-inspecting WAF / DB query
  monitoring) gets built, so that even a *re-introduced* body-borne attack would
  now be **seen** as well as blocked.

The loop closes: the vulnerability that was silent in Phase 5 becomes both
**un-exploitable** (the app fix) and **visible** (the new sensor) in Phase 8.

---

## Status

- [x] Kali staged as the attacker, reaching the target over the controlled, authorized channel (NAT'd behind the operator's IP).
- [x] **Vector 1 — SSH brute force** (hydra) detected: auth-failure burst → rule **5712**, then the successful-login pivot **5715** (T1110 → T1078). Temporary weak account removed afterward.
- [x] **Vector 2 — post-compromise** detected: new user (**5902** / T1136), sudo-to-root (**5402** / T1548.003), and FIM checksum change (**550**) with `report_changes` showing the exact added line. Real-time FIM on `/root` + `/etc` kept as a permanent improvement.
- [x] **Vector 3 — web attacks** via an nginx reverse proxy (port 80 to the attacker only): nikto + GET SQLi/XSS/traversal caught loudly (**31101** in the thousands, **31103/31105/31106**) — ~7,000 alerts.
- [x] **Key finding documented:** the POST SQLi login bypass **succeeded** (302 + valid session) with **zero** alerts — nginx logs omit the body — and the hardcoded `SECRET_KEY` makes sessions forgeable offline. Detection was inversely correlated with danger.
- [x] Caught-vs-missed table + remediation options (app-level logging / body-inspecting WAF / DB query monitoring) recorded.
- [ ] **Phase 8:** fix the planted flaws, prove the succeeded attacks now fail (regression flips 6/6 → 0/6) and the pipeline goes green by merit, and add the body-aware sensor so the silent attack becomes visible.
