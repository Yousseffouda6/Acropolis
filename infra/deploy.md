# Acropolis — Phase 3 cloud deploy runbook

This runbook provisions a single cloud VM, installs Docker, and runs the
**Acropolis Notes** container **bound to loopback only**, reachable from your
workstation through an SSH tunnel. None of the vulnerable app is exposed to the
public internet. The reasoning is in
[`../writeups/phase-3-cloud.md`](../writeups/phase-3-cloud.md); this file is the
how-to.

> **Placeholders — never commit real values.**
> `<PUBLIC_IP>` = the instance's public IP · `<KEY>.pem` = your SSH private key ·
> `<YOUR_IP>` = your workstation's public IP (find it with
> `curl -s https://checkip.amazonaws.com`). `*.pem` / `*.key` are gitignored so a
> key can never be committed.

---

## 0. What we build

| | |
| --- | --- |
| Provider / type | AWS EC2 `t3.micro` (free tier) |
| OS | Ubuntu 26.04 LTS |
| Region | `eu-central-1` |
| Inbound | TCP **22** (SSH) from `<YOUR_IP>/32` **only** |
| App port 5000 | **not** opened — loopback binding + SSH tunnel instead |
| OS user | `ubuntu` (non-root, has sudo); SSH **key only**, password auth off |

---

## 1. Provision the instance

In the EC2 console (or CLI), launch:

- **AMI:** Ubuntu Server 26.04 LTS (arm/x86 — `t3.micro` is x86_64).
- **Type:** `t3.micro` (free-tier eligible).
- **Region:** `eu-central-1`.
- **Key pair:** create or select one, and download `<KEY>.pem`. This is the only
  way in — keep it off version control (`*.pem` is gitignored) and `chmod 600` it.
- **Security group:** create a new one (configured in step 2). Do **not** accept
  the wizard's default "open 5000 / open HTTP" suggestions.

CLI sketch (placeholders only):

```bash
aws ec2 run-instances \
  --region eu-central-1 \
  --image-id <UBUNTU_2604_AMI_ID> \
  --instance-type t3.micro \
  --key-name <KEY> \
  --security-group-ids <SG_ID> \
  --associate-public-ip-address
```

---

## 2. Security group (the network control)

The security group is the lab's perimeter. **One** inbound rule; port 5000 is
never opened.

```bash
# allow SSH from your workstation ONLY (a /32, not 0.0.0.0/0)
aws ec2 authorize-security-group-ingress \
  --region eu-central-1 \
  --group-id <SG_ID> \
  --protocol tcp --port 22 --cidr <YOUR_IP>/32

# NOTE: there is deliberately NO rule for tcp/5000. The app is never
# internet-reachable. Egress is left at the default (allow all) for apt/docker.
```

Verify there is no 5000 rule:

```bash
aws ec2 describe-security-groups --group-ids <SG_ID> \
  --query 'SecurityGroups[0].IpPermissions'
# expect: a single tcp/22 entry scoped to <YOUR_IP>/32
```

If your home IP changes, update the `/32` — do not widen it to `0.0.0.0/0`.

---

## 3. First connection

```bash
chmod 600 <KEY>.pem
ssh -i <KEY>.pem ubuntu@<PUBLIC_IP>
```

You land as the non-root `ubuntu` user (sudo-capable). Password authentication is
disabled by the Ubuntu cloud image default; the key is the only credential.

---

## 4. Install + deploy (one script)

Bootstrap git, clone the repo, and run the idempotent deploy script. The script
installs Docker, builds the image, and runs the container bound to loopback.

```bash
sudo apt-get update -y && sudo apt-get install -y git
git clone https://github.com/Yousseffouda6/Acropolis.git ~/Acropolis
cd ~/Acropolis
./infra/deploy.sh
```

(Alternatively, fetch just the script — it clones the repo itself:
`curl -fsSL https://raw.githubusercontent.com/Yousseffouda6/Acropolis/main/infra/deploy.sh -o deploy.sh && chmod +x deploy.sh && ./deploy.sh`.)

Confirm the binding is loopback-only:

```bash
sudo docker ps --format '{{.Names}}\t{{.Ports}}'
# expect:  acropolis-notes   127.0.0.1:5000->5000/tcp
sudo ss -tlnp | grep 5000
# expect it bound to 127.0.0.1:5000, NOT 0.0.0.0:5000
```

---

## 5. Access via SSH tunnel

The app has no public port. Forward it to your workstation over SSH:

```bash
ssh -i <KEY>.pem -L 5000:localhost:5000 ubuntu@<PUBLIC_IP>
```

Leave that session open and browse **http://localhost:5000** on your workstation.
The traffic rides the encrypted SSH channel; the `-L 5000:localhost:5000` resolves
`localhost` on the *server* side, which is exactly where the container listens.

Sanity check from your workstation that the app is **not** directly reachable:

```bash
curl -m 5 http://<PUBLIC_IP>:5000/   # expect a timeout / connection refused
```

---

## 6. Redeploy / update

After pushing new commits, a redeploy is one command on the host:

```bash
cd ~/Acropolis && ./infra/deploy.sh
```

The script pulls `origin/main`, rebuilds, and replaces the container
(`--restart unless-stopped` brings it back after a reboot).

---

## 7. Operational notes

- **Stop / start:** `sudo docker stop acropolis-notes` / `sudo docker start acropolis-notes`.
- **Logs:** `sudo docker logs -f acropolis-notes`.
- **Fresh data:** each `deploy.sh` run recreates the container, which re-seeds the
  SQLite DB (the `FLAG{...}` note returns). The lab target is meant to be reset-friendly.
- **Do not** add a `-p 0.0.0.0:5000:5000` mapping or a 5000 security-group rule.
  That single change would put unauthenticated RCE on the open internet.
