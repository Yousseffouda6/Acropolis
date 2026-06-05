# Phase 4 — Blue Team: a SIEM that watches the target from outside it

Phase 3 put a deliberately vulnerable app on a live cloud host that is never
publicly exposed. Phase 4 gives that host a watcher: a **Wazuh** SIEM running on
its **own** cloud VM, monitoring the Acropolis box through an agent. This is the
defensive half of the lab — the eyes that Phase 5's attack will be seen by.

The phase turns on one design rule, the mirror of Phase 3's: **the thing that
watches must not live inside the thing it watches.** If the monitor shared a host
with the target, an attacker who popped the target would land on top of the
evidence. So the SIEM gets its own box.

The how-to (provisioning, Compose, certs, agent enrollment) is in
[`../detection/wazuh-deployment.md`](../detection/wazuh-deployment.md). This
writeup is the *why* — the architecture and the security model.

---

## The deployment at a glance

| | |
| --- | --- |
| SIEM host | AWS EC2 `m7i-flex.large` (free-tier eligible), Ubuntu, 8 GB RAM, 30 GB disk |
| Placement | Same VPC as the Acropolis host, **different Availability Zone**, `eu-central-1` |
| Stack | Wazuh single-node via Docker Compose, pinned to `v4.14.5` |
| Containers | `wazuh.manager` (analysis), `wazuh.indexer` (OpenSearch storage/search), `wazuh.dashboard` (web UI) |
| Dashboard | HTTPS/443 (self-signed), **never opened to the internet** — reached via SSH tunnel `-L 8443:localhost:443` |
| Agent ports | `1514/tcp` (events) + `1515/tcp` (enrollment), opened **only** to the Acropolis host's private IP `/32` |
| Monitored host | The Phase 3 Acropolis box, running a Wazuh agent pointed at the manager's **private** IP |

---

## What a SIEM/HIDS is — and why it gets its own host

A **SIEM** (Security Information and Event Management) is the place security
telemetry is collected, normalized, correlated, and alerted on. A **HIDS**
(Host-based Intrusion Detection System) is the sensor on each machine that
produces that telemetry: it watches files, logs, processes, and configuration on
the host itself, as opposed to a network IDS that watches packets on the wire.
Wazuh is both — a manager that does SIEM-style analysis and correlation, fed by
lightweight HIDS **agents** installed on the machines being watched.

The non-obvious decision is *where the manager runs*. It would be cheaper and
simpler to install it next to the app. That is exactly the wrong move:

- **The watched should not be able to silence the watcher.** Acropolis Notes has
  unauthenticated RCE by design (Phase 3). An attacker who exploits it gets code
  execution on the Acropolis host. If the SIEM lived there, that same compromise
  would hand the attacker the log store and alerting engine — they could wipe the
  evidence of their own intrusion. With the manager on a separate box, the agent
  ships events **off the host as they happen**; by the time an attacker thinks to
  cover their tracks, the record is already gone somewhere they can't reach.
- **Separation of duties / blast radius.** The target is disposable and weak by
  design; the monitor is the source of truth. Keeping them apart means a
  compromise of the workload does not compromise the detection.
- **Realism.** This is how production looks: endpoints run agents, a central SIEM
  aggregates. The lab mirrors the real topology rather than collapsing it for
  convenience.

So the SIEM is a second EC2 instance, in the **same VPC** as the target (so they
can talk over private addresses) but a **different Availability Zone** (so a
single-AZ failure doesn't take watcher and watched down together). Watcher and
watched, deliberately apart.

---

## Wazuh's three components

The single-node stack is three Docker containers, each with one job:

1. **`wazuh.manager` — the brain.** Receives events from agents, runs them through
   decoders and rules, raises alerts, and drives active response. This is the
   analysis engine and the agent's control plane.
2. **`wazuh.indexer` — the memory.** An OpenSearch instance that stores alerts and
   events and makes them searchable. This is the component with the appetite: it
   is why the box needs 8 GB of RAM and why the kernel needs `vm.max_map_count`
   raised (below).
3. **`wazuh.dashboard` — the face.** An OpenSearch-Dashboards web UI for querying
   events, viewing alerts, managing agents, and running the "Deploy new agent"
   wizard. This is the only component a human touches, and the only one with a
   listening port we care about exposing — carefully (below).

Single-node means all three run on the one VM. That is right-sized for a lab with
exactly one monitored host; a production deployment would scale the indexer into a
cluster, but here it would only burn free-tier resources.

---

## The agent model and its two ports

Detection data does not come from the SIEM reaching *into* the target. It comes
from an **agent on the target reaching out** to the manager. That direction
matters: the agent initiates the connection, so the target never has to accept an
inbound management port from the SIEM.

The agent and manager speak over exactly two ports:

- **`1515/tcp` — enrollment (one-time-ish).** The first time the agent registers,
  it talks to the manager on 1515 to obtain its keys. After enrollment this port
  sees little traffic.
- **`1514/tcp` — events (continuous).** Once enrolled, the agent streams its
  telemetry — file-integrity changes, collected logs, process and module data — to
  the manager on 1514 for the life of the deployment.

Both are pointed at the manager's **private** IP. The agent on the Acropolis box
is configured against `<SIEM_PRIVATE_IP>`, not a public address, so every byte of
agent↔manager traffic stays on the VPC's internal network and never crosses the
public internet.

---

## Defense in depth: keep the SIEM off the internet too

Phase 3 established the rule that the vulnerable app is never internet-reachable.
Phase 4 holds the SIEM to the same standard — a SIEM is a high-value target (it
holds the security record of the whole lab), so it is locked down with the same
layered approach. No single control is trusted.

1. **Dashboard is tunnel-only.** The Wazuh dashboard listens on HTTPS/443 with a
   self-signed certificate, and **443 is never opened in the security group**. It
   is reached exactly like the Phase 3 app: over an SSH local port-forward,
   `ssh -L 8443:localhost:443 ...`, then browse `https://localhost:8443` on the
   workstation. Reaching the UI therefore requires the SSH key *and* the allowed
   source IP — the web UI rides an already-authenticated, encrypted channel.
2. **Agent ports are scoped to one private `/32`.** Ports 1514 and 1515 are opened
   in the SIEM's security group **only** to the Acropolis host's private IP
   (`<AGENT_PRIVATE_IP>/32`), and only within the VPC. No other host — and nothing
   on the internet — can even attempt to connect to the manager. The single agent
   that is allowed to talk is named explicitly.
3. **Key-only SSH, non-root operation.** As on the Phase 3 host, login is by SSH
   key as a non-root sudo user; password auth is off. There is no shared secret to
   brute-force.
4. **Self-signed TLS in transit.** Indexer, manager, and dashboard communicate
   over TLS using certificates generated at deploy time; the dashboard's HTTPS is
   self-signed (acceptable because it is only ever reached over the SSH tunnel,
   which already authenticates the channel).

The layers compose: to read the SIEM you must hold the key and be the allowed IP
and tunnel in (layer 1); to feed the SIEM you must be the one named private host
inside the VPC (layer 2). Neither the dashboard nor the manager presents any
attack surface to the open internet.

---

## What the agent actually detects

The Wazuh agent on the Acropolis host runs several daemons, each a different lens
on the box — and, in Phase 5, a different chance to catch the attacker:

- **`syscheckd` — File Integrity Monitoring (FIM).** Watches key directories and
  files for creation, modification, and deletion, and reports the change with
  before/after hashes. A web shell dropped by the RCE, or a tampered config, shows
  up here.
- **`logcollector` — log collection.** Tails host logs (auth/`sudo`, system) and
  forwards them to the manager. SSH logins, privilege escalation, and service
  events become searchable alerts.
- **`modulesd` — vulnerability & configuration modules.** Runs the vulnerability
  detector (matching installed packages against CVE feeds) and configuration
  assessment (CIS-style policy checks), surfacing the host's weak spots.
- **`execd` — active response.** Can execute response actions (e.g. block an IP,
  kill a process) when a rule fires — the bridge from *detecting* to *reacting*.

Because the only ingress to the Acropolis host is a narrow, authenticated channel,
there is no internet background noise drowning the signal. The telemetry the agent
ships is almost entirely the lab's own activity, which makes Phase 5's attack
footprints clean to pick out.

---

## Lessons learned (the parts that didn't go to plan)

Three things bit during the build and are worth recording, because each is a real
cloud/ops gotcha rather than a Wazuh quirk:

1. **The AWS Free Plan blocks non-free-tier instance types.** The first instinct
   was a `t3.medium` for the indexer's memory needs — but it was blocked at launch
   under the Free Plan's allow-list. The fix was to choose a type that *is*
   free-tier eligible and still has the RAM: `m7i-flex.large` (8 GB). Lesson: check
   the account's plan constraints before sizing, not after the launch fails.
2. **The `wazuh-docker` `stable` branch was retired — pin a real version tag.**
   Cloning the `stable` branch (a long-standing habit) no longer resolves. The
   deployment pins an explicit release tag instead, `v4.14.5`, which also makes the
   build reproducible. Lesson: pin to a version, never a moving branch.
3. **The default 8 GB volume filled mid-pull — resized live.** The instance
   launched with the 8 GB root EBS default, which the Wazuh images exhausted while
   pulling. Rather than rebuild, the volume was grown in place: expand the EBS
   volume in the console, then on the host `growpart` the partition and `resize2fs`
   the filesystem — no reboot, no data loss. Lesson: size the disk for container
   images up front (30 GB here), and know the live-resize path for when you didn't.

A fourth, smaller prerequisite belongs with these: the OpenSearch-based indexer
requires the kernel's `vm.max_map_count` raised to **262144** (the default is far
lower), or the indexer container refuses to start. It is set before
`docker compose up` and persisted across reboots.

---

## How this sets up Phase 5

Phase 4 is the defensive instrument; Phase 5 is the experiment it was built for.
With the agent active and shipping telemetry to a manager the target can't reach:

- The **attacker** (the Kali VM) will exploit Acropolis Notes over the controlled
  channel — the SQLi, the IDOR, the YAML RCE — exactly as built.
- The **defender** will then hunt that attack here: pivot through the agent's FIM,
  auth logs, and process events in the dashboard, see what Wazuh's out-of-the-box
  rules caught, and — the real deliverable — **write custom detection rules for the
  blind spots** the defaults missed.

That catch/miss loop is the point of the whole lab: a vulnerability in the app
becomes an attack from Kali becomes an alert (or a silence) in Wazuh, and the
silences become new rules. Phase 5 ran exactly that experiment — and its headline
is a warning about this very setup: the agent's host rules caught the loud attacks,
but a successful, body-borne SQLi login bypass slipped past proxy-log-based web
detection entirely. See [`phase-5-attack-detect.md`](./phase-5-attack-detect.md).

---

## Status

- [x] Second EC2 instance (`m7i-flex.large`, 8 GB / 30 GB, Ubuntu, free-tier eligible) provisioned as a dedicated SIEM host.
- [x] Placed in the **same VPC** as the Acropolis host but a **different Availability Zone**, `eu-central-1`.
- [x] `vm.max_map_count` raised to `262144` for the OpenSearch indexer.
- [x] Wazuh single-node stack deployed via Docker Compose, pinned to `v4.14.5` (manager + indexer + dashboard).
- [x] Dashboard on HTTPS/443 (self-signed), **never internet-exposed** — accessed via SSH tunnel (`-L 8443:localhost:443`).
- [x] Agent ports `1514`/`1515` opened **only** to the Acropolis host's private IP `/32`, inside the VPC.
- [x] Wazuh agent installed on the Acropolis host, pointed at the manager's **private** IP, and active.
- [x] Agent detection surface live: FIM (`syscheckd`), log collection (`logcollector`), vuln/config (`modulesd`), active response (`execd`).
- [x] **Phase 5:** attacked Acropolis Notes from Kali and hunted the footprints here — the noisy scans lit up, the successful SQLi login bypass did not. See [`phase-5-attack-detect.md`](./phase-5-attack-detect.md).
