# Phase 3 — Cloud Security: a live target that is never publicly exposed

Phase 1 built a deliberately vulnerable app; Phase 2 scanned it. Phase 3 puts it
on a real cloud host so later phases have a **live** target to attack (Phase 5)
and monitor (Phase 4). The whole phase turns on one decision — and it is a
decision about what **not** to do: **do not expose the vulnerable app to the
public internet.**

The how-to (provisioning, security group, deploy) is in
[`../infra/deploy.md`](../infra/deploy.md); a redeploy is one idempotent script,
[`../infra/deploy.sh`](../infra/deploy.sh). This writeup is the *why* — the
security model.

---

## The deployment at a glance

| | |
| --- | --- |
| Host | AWS EC2 `t3.micro` (free tier), Ubuntu 26.04 LTS, `eu-central-1` |
| Runtime | Docker (`docker.io` from apt); image built on the host from this repo |
| Container | `-p 127.0.0.1:5000:5000` (loopback), `--restart unless-stopped` |
| Network | Security group: inbound **TCP 22 from the operator's IP only**; 5000 never opened |
| Identity | Non-root `ubuntu` user with sudo; **SSH key only**, password auth off |
| Access | An SSH local port-forward (`ssh -L 5000:localhost:5000`) — the only path in |
| Cost | AWS **Free Plan** (a hard credit cap, not just a warning) + a billing **budget alert**; `t3.micro` + small EBS stays inside the free tier |

---

## The core decision: don't put unauthenticated RCE on the internet

Acropolis Notes is not "a bit vulnerable." By design it has insecure YAML
deserialization (VULN #4) that yields **arbitrary code execution**, behind a login
that a one-line SQL injection (VULN #2) walks straight through. In effect the box
offers **unauthenticated remote code execution** to anyone who can reach port 5000.

The public internet is not a quiet place. Mass scanners (Shodan, Censys, and a
constant churn of botnets) sweep the entire IPv4 space for open ports continuously;
a fresh host with an open web port is typically probed within **minutes**. An
exposed Acropolis Notes would not be a teaching target — it would be someone
else's compromised host, mining crypto or pivoting, before the first lab exercise
even started.

So the deployment is built to be **live but unreachable from the open internet**.
That is not a limitation of the lab; it *is* the cloud-security lesson: you can
operate a deliberately weak workload safely if the architecture around it denies
untrusted reach by default.

---

## Defense in depth: four independent layers

No single control is trusted. Each of these layers, **on its own**, is enough to
keep the app off the public internet — so a mistake in any one of them is still
backstopped by the others.

1. **Network perimeter — security group.** Exactly one inbound rule: TCP 22 from
   the operator's `/32`. Port 5000 is **never** opened. Even SSH is not open to the
   world; only one source IP can knock.
2. **Exposure — loopback container binding.** The container is published as
   `127.0.0.1:5000:5000`, not `0.0.0.0:5000:5000`. Nothing listens on the host's
   public interface at all. *Even if the security group were misconfigured to open
   5000*, there would be no service on the public NIC to connect to. This is the
   layer that makes the perimeter mistake survivable.
3. **Identity — key-only SSH, non-root user.** Login is the `ubuntu` user over an
   SSH **key pair**; password authentication is off, so there is nothing to
   brute-force. Day-to-day operation is non-root; root is reached deliberately via
   `sudo`, which is logged.
4. **Access channel — SSH tunnel.** The app is reached only by forwarding it over
   SSH (`ssh -L 5000:localhost:5000`). Reaching the app therefore requires *both*
   possession of the private key *and* being the allowed source IP. The app's port
   rides an already-authenticated, encrypted channel.

The layers compose: to touch the app you must be the right IP (layer 1), hold the
key (layer 3), and tunnel in (layer 4) — and even then you are talking to a
service that only ever bound to localhost (layer 2).

---

## Least-privilege / IAM story

"Least privilege" on a single VM is about granting the minimum standing access at
every level:

- **Minimal open ports.** The attack surface is one port (22), scoped to one
  source. Everything else is closed. The app port is not a port at all from the
  network's point of view.
- **Key-based authentication, no passwords.** Credentials are asymmetric and
  off-box (the private key never leaves the operator's workstation; only the public
  key is on the server). There is no shared secret to leak or guess.
- **Non-root operator.** The `ubuntu` user holds no more privilege than it needs
  and escalates explicitly with `sudo`. Containers run via the Docker daemon rather
  than the login user holding root.
- **No standing cloud credentials on the host.** The box is not handed a broad
  instance role and no AWS keys are written to disk, so a compromise of the
  *workload* does not hand an attacker the *cloud account*. (Provisioning is done
  with the operator's own IAM identity, separately, from the workstation.)

The throughline: the blast radius of the deliberately vulnerable workload is
contained to this one disposable VM.

---

## Cost control: a hard cap, not just a warning

A vulnerable box that runs 24/7 is also a *billing* risk — a compromise can spin
up resources, and even honest mistakes (an oversized instance, a forgotten volume)
quietly accrue. Two controls keep the lab cheap and bounded, in the same
least-privilege spirit as the network model:

- **AWS Free Plan as a hard cap.** The account runs on the AWS Free Plan, which
  *caps* spend rather than merely tracking it: when the free credits are exhausted,
  paid usage is blocked instead of silently billed. That turns "I forgot to tear it
  down" from a surprise invoice into a stopped resource.
- **A billing budget alert.** A budget is configured to email at a low threshold,
  so any unexpected cost — a runaway resource, a misconfiguration — surfaces
  immediately rather than at month-end.
- **Right-sized, free-tier resources.** The host is a `t3.micro` on a small EBS
  volume, both inside the free tier, so steady-state cost is effectively zero; the
  cap and the alert only ever matter if something goes wrong.

Least privilege bounds the lab's blast radius not just in *access* but in *spend*.

---

## Why a controlled channel, not a public port

Phase 5 will attack this host, and Phase 4 will watch it. Both happen over the
**controlled channel**, not the open internet:

- The **attacker** (the Kali VM, Phase 5) reaches the target the same way the
  operator does — through the SSH tunnel / within the scoped lab — so the
  engagement stays authorized and bounded to systems the author owns.
- The **monitoring** (Wazuh, Phase 4) runs an agent **on this host**, shipping
  host and container telemetry (auth events, sudo, process and Docker activity) to
  the SIEM. Because the only ingress is a narrow, authenticated channel, the
  signal-to-noise ratio is high: there is no internet background radiation drowning
  out the lab's own activity, which makes the Phase 5 attack footprints clean to
  detect.

Running the target through a controlled channel is what lets the same box be both
"realistically deployed" and "safe to leave running."

---

## Redeploy in one command

`infra/deploy.sh` is idempotent: it installs Docker + git if missing, pulls the
latest `main`, rebuilds the image, and replaces the container with the loopback
binding and `--restart unless-stopped`. After pushing new commits:

```bash
cd ~/Acropolis && ./infra/deploy.sh
```

No app code is modified by deployment — the planted vulnerabilities ship exactly
as built in Phase 1, which is the point: Phases 4 and 5 act on the *same* artifact.

---

## Status

- [x] EC2 `t3.micro` (Ubuntu 26.04, `eu-central-1`, free tier) provisioned.
- [x] Security group: inbound SSH/22 from the operator's IP only; **port 5000 never opened**.
- [x] Docker installed (`docker.io`); image built on the host from this repo.
- [x] Container runs bound to `127.0.0.1:5000` with `--restart unless-stopped`.
- [x] Access only via SSH local port-forward; key-only SSH; non-root `ubuntu` user.
- [x] Idempotent redeploy (`infra/deploy.sh`) + runbook (`infra/deploy.md`); no key/IP/secret committed.
- [x] Cost bounded by the AWS Free Plan (hard cap) plus a billing budget alert; free-tier `t3.micro` + small EBS.
- [x] **Phase 4:** Wazuh agent installed on this host, shipping host + container telemetry — see [`phase-4-blueteam.md`](./phase-4-blueteam.md).
- [x] **Phase 5:** attacked over the controlled channel and the footprints hunted in Wazuh — see [`phase-5-attack-detect.md`](./phase-5-attack-detect.md).
